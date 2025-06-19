package androidx.core.app;

import android.app.NotificationChannel;
import android.app.NotificationChannelGroup;
import android.os.Build;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/* renamed from: androidx.core.app.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1028o {
    public final String a;
    public final CharSequence b;
    public final String c;

    public C1028o(NotificationChannelGroup notificationChannelGroup) {
        this(notificationChannelGroup, Collections.EMPTY_LIST);
    }

    public final void a(List list) {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            NotificationChannel notificationChannel = (NotificationChannel) it2.next();
            if (this.a.equals(notificationChannel.getGroup())) {
                arrayList.add(new C1026m(notificationChannel));
            }
        }
    }

    public C1028o(NotificationChannelGroup notificationChannelGroup, List list) {
        String id = notificationChannelGroup.getId();
        List list2 = Collections.EMPTY_LIST;
        id.getClass();
        this.a = id;
        this.b = notificationChannelGroup.getName();
        int i = Build.VERSION.SDK_INT;
        if (i >= 28) {
            this.c = AbstractC1027n.b(notificationChannelGroup);
        }
        if (i < 28) {
            a(list);
        } else {
            AbstractC1027n.d(notificationChannelGroup);
            a(notificationChannelGroup.getChannels());
        }
    }
}
