package androidx.core.app;

import android.app.Notification;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class E extends F {
    public final ArrayList a = new ArrayList();
    public final ArrayList b = new ArrayList();
    public final Q c;
    public Boolean d;

    public E(Q q) {
        if (TextUtils.isEmpty(q.a)) {
            throw new IllegalArgumentException("User's name must not be empty.");
        }
        this.c = q;
    }

    @Override // androidx.core.app.F
    public final void addCompatExtras(Bundle bundle) {
        super.addCompatExtras(bundle);
        Q q = this.c;
        bundle.putCharSequence("android.selfDisplayName", q.a);
        bundle.putBundle("android.messagingStyleUser", q.a());
        bundle.putCharSequence("android.hiddenConversationTitle", null);
        ArrayList arrayList = this.a;
        if (!arrayList.isEmpty()) {
            bundle.putParcelableArray("android.messages", D.a(arrayList));
        }
        ArrayList arrayList2 = this.b;
        if (!arrayList2.isEmpty()) {
            bundle.putParcelableArray("android.messages.historic", D.a(arrayList2));
        }
        Boolean bool = this.d;
        if (bool != null) {
            bundle.putBoolean("android.isGroupConversation", bool.booleanValue());
        }
    }

    @Override // androidx.core.app.F
    public final void apply(InterfaceC1024k interfaceC1024k) {
        Boolean bool;
        Notification.MessagingStyle messagingStyleB;
        C1034v c1034v = this.mBuilder;
        boolean zBooleanValue = false;
        if ((c1034v == null || c1034v.a.getApplicationInfo().targetSdkVersion >= 28 || this.d != null) && (bool = this.d) != null) {
            zBooleanValue = bool.booleanValue();
        }
        this.d = Boolean.valueOf(zBooleanValue);
        int i = Build.VERSION.SDK_INT;
        Q q = this.c;
        if (i >= 28) {
            q.getClass();
            messagingStyleB = A.a(AbstractC1027n.g(q));
        } else {
            messagingStyleB = y.b(q.a);
        }
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            y.a(messagingStyleB, ((D) it2.next()).b());
        }
        Iterator it3 = this.b.iterator();
        while (it3.hasNext()) {
            z.a(messagingStyleB, ((D) it3.next()).b());
        }
        if (this.d.booleanValue() || Build.VERSION.SDK_INT >= 28) {
            y.c(messagingStyleB, null);
        }
        if (Build.VERSION.SDK_INT >= 28) {
            A.b(messagingStyleB, this.d.booleanValue());
        }
        messagingStyleB.setBuilder(((H) interfaceC1024k).b);
    }

    @Override // androidx.core.app.F
    public final String getClassName() {
        return "androidx.core.app.NotificationCompat$MessagingStyle";
    }
}
