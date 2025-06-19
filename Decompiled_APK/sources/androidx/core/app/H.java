package androidx.core.app;

import android.app.Notification;
import android.app.RemoteInput;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.widget.RemoteViews;
import androidx.collection.C0209g;
import androidx.core.graphics.drawable.IconCompat;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class H implements InterfaceC1024k {
    public final Context a;
    public final Notification.Builder b;
    public final C1034v c;
    public final Bundle d;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r17v3, types: [java.lang.Throwable] */
    public H(C1034v c1034v) {
        CharSequence[] charSequenceArr;
        Bundle[] bundleArr;
        ArrayList arrayList;
        new ArrayList();
        this.d = new Bundle();
        this.c = c1034v;
        Context context = c1034v.a;
        this.a = context;
        Notification.Builder builder = new Notification.Builder(context, c1034v.v);
        this.b = builder;
        Notification notification = c1034v.y;
        CharSequence[] charSequenceArr2 = null;
        int i = 0;
        builder.setWhen(notification.when).setSmallIcon(notification.icon, notification.iconLevel).setContent(notification.contentView).setTicker(notification.tickerText, null).setVibrate(notification.vibrate).setLights(notification.ledARGB, notification.ledOnMS, notification.ledOffMS).setOngoing((notification.flags & 2) != 0).setOnlyAlertOnce((notification.flags & 8) != 0).setAutoCancel((notification.flags & 16) != 0).setDefaults(notification.defaults).setContentTitle(c1034v.e).setContentText(c1034v.f).setContentInfo(null).setContentIntent(c1034v.g).setDeleteIntent(notification.deleteIntent).setFullScreenIntent(null, (notification.flags & 128) != 0).setNumber(c1034v.i).setProgress(0, 0, false);
        IconCompat iconCompat = c1034v.h;
        builder.setLargeIcon(iconCompat == null ? null : iconCompat.e(context));
        builder.setSubText(c1034v.m).setUsesChronometer(false).setPriority(c1034v.j);
        Iterator it2 = c1034v.b.iterator();
        while (it2.hasNext()) {
            C1029p c1029p = (C1029p) it2.next();
            IconCompat iconCompatA = c1029p.a();
            Notification.Action.Builder builder2 = new Notification.Action.Builder(iconCompatA != null ? iconCompatA.e(null) : null, c1029p.g, c1029p.h);
            T[] tArr = c1029p.c;
            if (tArr != null) {
                int length = tArr.length;
                RemoteInput[] remoteInputArr = new RemoteInput[length];
                if (tArr.length > 0) {
                    T t = tArr[0];
                    throw null;
                }
                for (int i2 = 0; i2 < length; i2++) {
                    builder2.addRemoteInput(remoteInputArr[i2]);
                }
            }
            Bundle bundle = c1029p.a;
            Bundle bundle2 = bundle != null ? new Bundle(bundle) : new Bundle();
            boolean z = c1029p.d;
            bundle2.putBoolean("android.support.allowGeneratedReplies", z);
            int i3 = Build.VERSION.SDK_INT;
            builder2.setAllowGeneratedReplies(z);
            bundle2.putInt("android.support.action.semanticAction", 0);
            if (i3 >= 28) {
                AbstractC1027n.f(builder2);
            }
            if (i3 >= 29) {
                AbstractC1020g.e(builder2);
            }
            if (i3 >= 31) {
                G.a(builder2);
            }
            bundle2.putBoolean("android.support.action.showsUserInterface", c1029p.e);
            builder2.addExtras(bundle2);
            this.b.addAction(builder2.build());
        }
        Bundle bundle3 = c1034v.p;
        if (bundle3 != null) {
            this.d.putAll(bundle3);
        }
        int i4 = Build.VERSION.SDK_INT;
        this.b.setShowWhen(c1034v.k);
        this.b.setLocalOnly(c1034v.n);
        this.b.setGroup(null);
        this.b.setSortKey(null);
        this.b.setGroupSummary(false);
        this.b.setCategory(c1034v.o);
        this.b.setColor(c1034v.q);
        this.b.setVisibility(c1034v.r);
        this.b.setPublicVersion(c1034v.s);
        this.b.setSound(notification.sound, notification.audioAttributes);
        ArrayList arrayList2 = c1034v.z;
        ArrayList arrayList3 = c1034v.c;
        if (i4 < 28) {
            if (arrayList3 == null) {
                arrayList = null;
            } else {
                arrayList = new ArrayList(arrayList3.size());
                Iterator it3 = arrayList3.iterator();
                while (it3.hasNext()) {
                    Q q = (Q) it3.next();
                    String str = q.b;
                    if (str == null) {
                        CharSequence charSequence = q.a;
                        str = charSequence != null ? "name:" + ((Object) charSequence) : "";
                    }
                    arrayList.add(str);
                }
            }
            if (arrayList != null) {
                if (arrayList2 == null) {
                    arrayList2 = arrayList;
                } else {
                    C0209g c0209g = new C0209g(arrayList2.size() + arrayList.size());
                    c0209g.addAll(arrayList);
                    c0209g.addAll(arrayList2);
                    arrayList2 = new ArrayList(c0209g);
                }
            }
        }
        if (arrayList2 != null && !arrayList2.isEmpty()) {
            Iterator it4 = arrayList2.iterator();
            while (it4.hasNext()) {
                this.b.addPerson((String) it4.next());
            }
        }
        ArrayList arrayList4 = c1034v.d;
        if (arrayList4.size() > 0) {
            if (c1034v.p == null) {
                c1034v.p = new Bundle();
            }
            Bundle bundle4 = c1034v.p.getBundle("android.car.EXTENSIONS");
            bundle4 = bundle4 == null ? new Bundle() : bundle4;
            Bundle bundle5 = new Bundle(bundle4);
            Bundle bundle6 = new Bundle();
            int i5 = 0;
            while (i5 < arrayList4.size()) {
                String string = Integer.toString(i5);
                C1029p c1029p2 = (C1029p) arrayList4.get(i5);
                Bundle bundle7 = new Bundle();
                IconCompat iconCompatA2 = c1029p2.a();
                ?? r17 = charSequenceArr2;
                bundle7.putInt("icon", iconCompatA2 != null ? iconCompatA2.b() : i);
                bundle7.putCharSequence("title", c1029p2.g);
                bundle7.putParcelable("actionIntent", c1029p2.h);
                Bundle bundle8 = c1029p2.a;
                Bundle bundle9 = bundle8 != null ? new Bundle(bundle8) : new Bundle();
                bundle9.putBoolean("android.support.allowGeneratedReplies", c1029p2.d);
                bundle7.putBundle("extras", bundle9);
                T[] tArr2 = c1029p2.c;
                if (tArr2 == null) {
                    bundleArr = r17;
                } else {
                    bundleArr = new Bundle[tArr2.length];
                    if (tArr2.length > 0) {
                        T t2 = tArr2[0];
                        new Bundle();
                        throw r17;
                    }
                }
                bundle7.putParcelableArray("remoteInputs", bundleArr);
                bundle7.putBoolean("showsUserInterface", c1029p2.e);
                bundle7.putInt("semanticAction", 0);
                bundle6.putBundle(string, bundle7);
                i5++;
                i = 0;
                charSequenceArr2 = r17;
            }
            charSequenceArr = charSequenceArr2;
            bundle4.putBundle("invisible_actions", bundle6);
            bundle5.putBundle("invisible_actions", bundle6);
            if (c1034v.p == null) {
                c1034v.p = new Bundle();
            }
            c1034v.p.putBundle("android.car.EXTENSIONS", bundle4);
            this.d.putBundle("android.car.EXTENSIONS", bundle5);
        } else {
            charSequenceArr = null;
        }
        int i6 = Build.VERSION.SDK_INT;
        this.b.setExtras(c1034v.p);
        this.b.setRemoteInputHistory(charSequenceArr);
        RemoteViews remoteViews = c1034v.t;
        if (remoteViews != null) {
            this.b.setCustomContentView(remoteViews);
        }
        RemoteViews remoteViews2 = c1034v.u;
        if (remoteViews2 != null) {
            this.b.setCustomBigContentView(remoteViews2);
        }
        this.b.setBadgeIconType(0);
        this.b.setSettingsText(null);
        this.b.setShortcutId(c1034v.w);
        this.b.setTimeoutAfter(0L);
        this.b.setGroupAlertBehavior(0);
        if (!TextUtils.isEmpty(c1034v.v)) {
            this.b.setSound(null).setDefaults(0).setLights(0, 0, 0).setVibrate(null);
        }
        if (i6 >= 28) {
            Iterator it5 = arrayList3.iterator();
            while (it5.hasNext()) {
                Q q2 = (Q) it5.next();
                Notification.Builder builder3 = this.b;
                q2.getClass();
                AbstractC1027n.a(builder3, AbstractC1027n.g(q2));
            }
        }
        if (Build.VERSION.SDK_INT >= 29) {
            AbstractC1020g.c(this.b, c1034v.x);
            AbstractC1020g.d(this.b);
        }
    }
}
