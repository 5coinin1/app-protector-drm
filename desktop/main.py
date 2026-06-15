"""Mini Desktop Client (kiểu Steam) — login, thư viện app, bấm Play để chạy.

Chạy: python main.py   (cần server đang chạy: xem ../server)
"""
import threading

import customtkinter as ctk

import api
import launcher_bridge
import session

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Chu kỳ tự đồng bộ thư viện với server (ms). Bắt thay đổi grant/revoke/xóa gần như tức thì.
POLL_MS = 8000


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Mini Client — Account-based DRM")
        self.geometry("560x640")
        self.minsize(480, 520)

        self.user = None
        self.tokens = None
        self.offline = False
        self._poll_after = None     # id lịch poll tự động (Tkinter after)
        self._last_sig = None       # chữ ký thư viện đã render -> chỉ vẽ lại khi đổi
        self._refreshing = False    # tránh chồng nhiều request poll

        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True, padx=16, pady=16)

        # Tự đăng nhập lại nếu có session đã lưu (hỗ trợ offline cơ bản).
        saved = session.load()
        if saved and saved.get("tokens"):
            self.user = saved["user"]
            self.tokens = saved["tokens"]
            self.show_library(initial_cache=saved.get("library", []))
        else:
            self.show_login()

    # ---------- helpers ----------
    def _clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    # ---------- Login screen ----------
    def show_login(self):
        self._clear()
        ctk.CTkLabel(self.container, text="🎮  Mini Client",
                     font=ctk.CTkFont(size=26, weight="bold")).pack(pady=(40, 4))
        ctk.CTkLabel(self.container, text="Account-based DRM",
                     text_color="gray").pack(pady=(0, 30))

        form = ctk.CTkFrame(self.container)
        form.pack(padx=40, fill="x")

        ctk.CTkLabel(form, text="Email").pack(anchor="w", padx=20, pady=(20, 2))
        self.email_entry = ctk.CTkEntry(form, placeholder_text="email@example.com", width=320)
        self.email_entry.pack(padx=20)

        ctk.CTkLabel(form, text="Mật khẩu").pack(anchor="w", padx=20, pady=(14, 2))
        self.pw_entry = ctk.CTkEntry(form, placeholder_text="••••••••", show="•", width=320)
        self.pw_entry.pack(padx=20)
        self.pw_entry.bind("<Return>", lambda e: self.do_login())

        self.login_btn = ctk.CTkButton(form, text="Đăng nhập", command=self.do_login, width=320)
        self.login_btn.pack(padx=20, pady=20)

        self.login_status = ctk.CTkLabel(self.container, text="", text_color="#ff6b6b")
        self.login_status.pack(pady=8)

    def do_login(self):
        email = self.email_entry.get().strip()
        pw = self.pw_entry.get()
        if not email or not pw:
            self.login_status.configure(text="Nhập email và mật khẩu")
            return
        self.login_btn.configure(state="disabled", text="Đang đăng nhập...")
        self.login_status.configure(text="")

        def work():
            try:
                res = api.login(email, pw)
            except api.NetworkError:
                self.after(0, lambda: self._login_done(err="Không kết nối được server"))
            except api.ApiError as e:
                self.after(0, lambda: self._login_done(err=str(e)))
            else:
                self.after(0, lambda: self._login_ok(res))

        threading.Thread(target=work, daemon=True).start()

    def _login_done(self, err):
        self.login_btn.configure(state="normal", text="Đăng nhập")
        self.login_status.configure(text=err)

    def _login_ok(self, res):
        self.user = res["user"]
        self.tokens = res["tokens"]
        session.save(self.user, self.tokens)
        self.show_library()

    # ---------- Library screen ----------
    def show_library(self, initial_cache=None):
        self._clear()

        header = ctk.CTkFrame(self.container, fg_color="transparent")
        header.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(header, text="Thư viện của tôi",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")
        ctk.CTkButton(header, text="Đăng xuất", width=90, fg_color="gray30",
                      hover_color="gray20", command=self.do_logout).pack(side="right")
        ctk.CTkButton(header, text="🔄 Làm mới", width=100, fg_color="gray30",
                      hover_color="gray20", command=self.refresh_library).pack(side="right", padx=(0, 8))

        who = self.user.get("email", "?") if self.user else "?"
        self.sub_label = ctk.CTkLabel(self.container, text=f"Xin chào, {who}", text_color="gray")
        self.sub_label.pack(anchor="w", pady=(0, 8))

        self.list_frame = ctk.CTkScrollableFrame(self.container, label_text="")
        self.list_frame.pack(fill="both", expand=True)

        self.play_status = ctk.CTkLabel(self.container, text="", text_color="gray")
        self.play_status.pack(pady=6)

        # Hiện cache trước (mượt + offline), rồi đồng bộ từ server.
        self._last_sig = None
        if initial_cache:
            self._render_library(initial_cache, from_cache=True)
        self.refresh_library()
        self._start_poll()

    def refresh_library(self):
        if self._refreshing:
            return
        self._refreshing = True

        def work():
            try:
                lib = api.get_library(self.tokens["access_token"])
            except api.NetworkError:
                self.after(0, self._library_offline)
            except api.ApiError as e:
                self.after(0, lambda: self._library_error(str(e)))
            else:
                self.after(0, lambda: self._library_ok(lib))
            finally:
                self.after(0, self._refresh_done)

        threading.Thread(target=work, daemon=True).start()

    def _refresh_done(self):
        self._refreshing = False

    # ---------- Tự đồng bộ định kỳ (poll server) ----------
    def _start_poll(self):
        self._stop_poll()
        self._poll_after = self.after(POLL_MS, self._poll)

    def _stop_poll(self):
        if self._poll_after is not None:
            try:
                self.after_cancel(self._poll_after)
            except Exception:
                pass
            self._poll_after = None

    def _poll(self):
        if not self.tokens:   # đã đăng xuất -> dừng
            return
        self.refresh_library()
        self._poll_after = self.after(POLL_MS, self._poll)

    def _library_ok(self, lib):
        self.offline = False
        session.update_library(lib)
        self._render_library(lib, from_cache=False)

    def _library_offline(self):
        self.offline = True
        cached = (session.load() or {}).get("library", [])
        self.sub_label.configure(text=f"{self.user.get('email','?')}  •  ⚠ OFFLINE (dùng dữ liệu đã lưu)")
        self._render_library(cached, from_cache=True)

    def _library_error(self, msg):
        # Token hỏng -> về màn login
        self._stop_poll()
        session.clear()
        self.show_login()
        self.login_status.configure(text=msg)

    def _render_library(self, lib, from_cache):
        # Chữ ký gồm cả trạng thái đã-cài: chỉ vẽ lại khi thực sự đổi (tránh nhấp nháy mỗi lần poll).
        sig = tuple((it["product_id"], it.get("name"), it.get("version"),
                     launcher_bridge.is_installed(it["product_id"])) for it in lib)
        if sig == self._last_sig:
            return
        self._last_sig = sig

        for w in self.list_frame.winfo_children():
            w.destroy()

        if not lib:
            ctk.CTkLabel(self.list_frame, text="Chưa sở hữu app nào.\nNhờ admin cấp quyền trong dashboard.",
                         text_color="gray").pack(pady=40)
            return

        for item in lib:
            self._app_card(item)

    def _app_card(self, item):
        pid = item["product_id"]
        card = ctk.CTkFrame(self.list_frame)
        card.pack(fill="x", pady=6, padx=4)

        info = ctk.CTkFrame(card, fg_color="transparent")
        info.pack(side="left", fill="both", expand=True, padx=12, pady=10)
        ctk.CTkLabel(info, text=item.get("name", pid),
                     font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(info, text=f"{pid}  •  v{item.get('version','?')}",
                     text_color="gray", font=ctk.CTkFont(size=11)).pack(anchor="w")

        installed = launcher_bridge.is_installed(pid)
        if installed:
            # Gỡ cài đặt (xóa file khỏi máy, vẫn giữ quyền) + Play.
            ctk.CTkButton(card, text="🗑", width=40, fg_color="gray30", hover_color="#c92a2a",
                          command=lambda p=pid: self.do_uninstall(p)).pack(side="right", padx=(0, 12), pady=10)
            ctk.CTkButton(card, text="▶  Play", width=90,
                          command=lambda p=pid: self.do_play(p)).pack(side="right", pady=10)
        else:
            ctk.CTkButton(card, text="⬇  Cài đặt", width=90, fg_color="#2f9e44",
                          hover_color="#268a3a",
                          command=lambda p=pid: self.do_install(p)).pack(side="right", padx=12, pady=10)

    # ---------- Play ----------
    def do_play(self, product_id):
        self.play_status.configure(text=f"Đang khởi chạy {product_id}...", text_color="gray")

        def work():
            code, out = launcher_bridge.play(product_id, self.tokens["access_token"])
            self.after(0, lambda: self._play_done(product_id, code, out))

        threading.Thread(target=work, daemon=True).start()

    def _play_done(self, product_id, code, out):
        if code == 0:
            self.play_status.configure(text=f"✅ {product_id} đã chạy xong (exit 0)", text_color="#51cf66")
        else:
            self.play_status.configure(text=f"❌ {product_id} bị chặn / lỗi (exit {code})", text_color="#ff6b6b")
        self._show_output(product_id, code, out)

    def _show_output(self, product_id, code, out):
        win = ctk.CTkToplevel(self)
        win.title(f"Kết quả chạy: {product_id}  (exit {code})")
        win.geometry("620x420")
        box = ctk.CTkTextbox(win, font=ctk.CTkFont(family="Consolas", size=12))
        box.pack(fill="both", expand=True, padx=10, pady=10)
        box.insert("1.0", out or "(không có output)")
        box.configure(state="disabled")
        win.after(100, win.lift)

    # ---------- Uninstall (gỡ khỏi máy, vẫn giữ quyền) ----------
    def do_uninstall(self, product_id):
        from tkinter import messagebox
        if not messagebox.askyesno(
                "Gỡ cài đặt",
                f"Gỡ '{product_id}' khỏi máy?\n\n"
                "App sẽ bị xóa khỏi máy này, nhưng bạn VẪN GIỮ quyền sở hữu "
                "và có thể bấm Cài đặt để tải lại bất cứ lúc nào."):
            return
        try:
            launcher_bridge.uninstall(product_id)
        except Exception as e:
            self.play_status.configure(text=f"❌ Gỡ thất bại: {e}", text_color="#ff6b6b")
            return
        self.play_status.configure(text=f"✅ Đã gỡ {product_id} khỏi máy (vẫn còn quyền)",
                                   text_color="#51cf66")
        # Vẽ lại ngay từ cache để nút đổi Play -> Cài đặt, rồi đồng bộ lại với server.
        cached = (session.load() or {}).get("library", [])
        self._last_sig = None
        self._render_library(cached, from_cache=True)
        self.refresh_library()

    # ---------- Install ----------
    def do_install(self, product_id):
        self.play_status.configure(text=f"Đang cài {product_id}... (tải từ server)", text_color="gray")

        def work():
            try:
                launcher_bridge.install(product_id, self.tokens["access_token"])
            except api.NetworkError:
                self.after(0, lambda: self.play_status.configure(
                    text="❌ Mất kết nối khi tải app", text_color="#ff6b6b"))
            except api.ApiError as e:
                self.after(0, lambda: self.play_status.configure(
                    text=f"❌ Cài thất bại: {e}", text_color="#ff6b6b"))
            except Exception as e:
                self.after(0, lambda: self.play_status.configure(
                    text=f"❌ Lỗi cài: {e}", text_color="#ff6b6b"))
            else:
                self.after(0, lambda: self._install_done(product_id))

        threading.Thread(target=work, daemon=True).start()

    def _install_done(self, product_id):
        self.play_status.configure(text=f"✅ Đã cài {product_id} — bấm Play", text_color="#51cf66")
        self.refresh_library()

    # ---------- Logout ----------
    def do_logout(self):
        self._stop_poll()
        session.clear()
        self.user = self.tokens = None
        self._last_sig = None
        self.show_login()


if __name__ == "__main__":
    App().mainloop()
