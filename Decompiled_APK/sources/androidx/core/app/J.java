package androidx.core.app;

import android.app.Notification;
import android.os.Parcel;

/* loaded from: classes.dex */
public final class J implements N {
    public final String a;
    public final int b;
    public final String c;
    public final Notification d;

    public J(String str, int i, String str2, Notification notification) {
        this.a = str;
        this.b = i;
        this.c = str2;
        this.d = notification;
    }

    public final void a(android.support.v4.app.c cVar) {
        String str = this.a;
        int i = this.b;
        String str2 = this.c;
        android.support.v4.app.a aVar = (android.support.v4.app.a) cVar;
        aVar.getClass();
        Parcel parcelObtain = Parcel.obtain();
        try {
            parcelObtain.writeInterfaceToken(android.support.v4.app.c.P);
            parcelObtain.writeString(str);
            parcelObtain.writeInt(i);
            parcelObtain.writeString(str2);
            Notification notification = this.d;
            if (notification != null) {
                parcelObtain.writeInt(1);
                notification.writeToParcel(parcelObtain, 0);
            } else {
                parcelObtain.writeInt(0);
            }
            aVar.a.transact(1, parcelObtain, null, 1);
        } finally {
            parcelObtain.recycle();
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NotifyTask[packageName:");
        sb.append(this.a);
        sb.append(", id:");
        sb.append(this.b);
        sb.append(", tag:");
        return android.support.v4.media.session.a.t(sb, this.c, "]");
    }
}
