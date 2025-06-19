package androidx.core.app;

import android.app.Notification;

/* renamed from: androidx.core.app.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1032t extends F {
    public CharSequence a;

    public final void a(CharSequence charSequence) {
        this.mBigContentTitle = C1034v.b(charSequence);
    }

    @Override // androidx.core.app.F
    public final void apply(InterfaceC1024k interfaceC1024k) {
        Notification.BigTextStyle bigTextStyleBigText = new Notification.BigTextStyle(((H) interfaceC1024k).b).setBigContentTitle(this.mBigContentTitle).bigText(this.a);
        if (this.mSummaryTextSet) {
            bigTextStyleBigText.setSummaryText(this.mSummaryText);
        }
    }

    public final void b(CharSequence charSequence) {
        this.mSummaryText = C1034v.b(charSequence);
        this.mSummaryTextSet = true;
    }

    @Override // androidx.core.app.F
    public final String getClassName() {
        return "androidx.core.app.NotificationCompat$BigTextStyle";
    }
}
