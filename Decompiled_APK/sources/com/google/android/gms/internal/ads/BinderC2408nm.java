package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Parcel;
import android.os.RemoteException;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.app.NotificationManagerCompat;
import com.google.android.gms.ads.internal.offline.buffering.zza;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: com.google.android.gms.internal.ads.nm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2408nm extends AbstractBinderC2814x5 implements InterfaceC2783wb {
    public static final /* synthetic */ int h = 0;
    public final HashMap a;
    public final Context b;
    public final Hk c;
    public final com.google.android.gms.ads.internal.util.client.k d;
    public final C2107gm e;
    public String f;
    public String g;

    public BinderC2408nm(Context context, C2107gm c2107gm, com.google.android.gms.ads.internal.util.client.k kVar, Hk hk) {
        super("com.google.android.gms.ads.internal.offline.IOfflineUtils");
        this.a = new HashMap();
        this.b = context;
        this.c = hk;
        this.d = kVar;
        this.e = c2107gm;
    }

    public static void e4(Context context, Hk hk, C2107gm c2107gm, String str, String str2, Map map) {
        String strA;
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        String str3 = true != jVar.h.a(context) ? "offline" : "online";
        if (hk != null) {
            Fi fiA = hk.a();
            fiA.o("gqi", str);
            fiA.o("action", str2);
            fiA.o("device_connectivity", str3);
            jVar.k.getClass();
            fiA.o("event_timestamp", String.valueOf(System.currentTimeMillis()));
            for (Map.Entry entry : map.entrySet()) {
                fiA.o((String) entry.getKey(), (String) entry.getValue());
            }
            strA = ((Hk) fiA.c).a.f.a((ConcurrentHashMap) fiA.b);
        } else {
            strA = "";
        }
        String str4 = strA;
        com.google.android.gms.ads.internal.j.C.k.getClass();
        com.android.volley.toolbox.d dVar = new com.android.volley.toolbox.d(2, System.currentTimeMillis(), str, str4);
        c2107gm.getClass();
        c2107gm.d(new C1732Mb(26, c2107gm, dVar));
    }

    public static final PendingIntent g4(Context context, String str, String str2, String str3) {
        Intent intent = new Intent();
        intent.setAction(str);
        intent.putExtra("offline_notification_action", str);
        intent.putExtra("gws_query_id", str2);
        intent.putExtra("uri", str3);
        if (Build.VERSION.SDK_INT < 29 || !str.equals("offline_notification_clicked")) {
            intent.setClassName(context, "com.google.android.gms.ads.AdService");
            return PendingIntent.getService(context, 0, Vs.a(1140850688, intent), 1140850688);
        }
        intent.setClassName(context, "com.google.android.gms.ads.NotificationHandlerActivity");
        return PendingIntent.getActivity(context, 0, Vs.a(201326592, intent), 201326592);
    }

    public static String h4(int i, String str) {
        Resources resourcesB = com.google.android.gms.ads.internal.j.C.h.b();
        if (resourcesB != null) {
            try {
                return resourcesB.getString(i);
            } catch (Resources.NotFoundException unused) {
            }
        }
        return str;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x00d7  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void J3(com.google.android.gms.dynamic.a r9, com.google.android.gms.ads.internal.offline.buffering.zza r10) {
        /*
            Method dump skipped, instructions count: 284
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.BinderC2408nm.J3(com.google.android.gms.dynamic.a, com.google.android.gms.ads.internal.offline.buffering.zza):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    public final void Q1(com.google.android.gms.dynamic.a aVar) throws IllegalAccessException, Resources.NotFoundException, InstantiationException, IllegalArgumentException, InvocationTargetException {
        C2063fm c2063fm = (C2063fm) com.google.android.gms.dynamic.b.I3(aVar);
        Activity activity = c2063fm.a;
        this.f = c2063fm.c;
        this.g = c2063fm.d;
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.w8)).booleanValue();
        com.google.android.gms.ads.internal.overlay.d dVar = c2063fm.b;
        if (zBooleanValue) {
            k4(activity, dVar);
            return;
        }
        i4(this.f, "dialog_impression", Gu.g);
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        AlertDialog.Builder builderJ = com.google.android.gms.ads.internal.util.F.j(activity);
        builderJ.setTitle(h4(R.string.offline_opt_in_title, "Open ad when you're back online.")).setMessage(h4(R.string.offline_opt_in_message, "We'll send you a notification with a link to the advertiser site.")).setPositiveButton(h4(R.string.offline_opt_in_confirm, "OK"), new DialogInterfaceOnClickListenerC2151hm(this, activity, dVar, 1)).setNegativeButton(h4(R.string.offline_opt_in_decline, "No thanks"), new DialogInterfaceOnClickListenerC2194im(1, this, dVar)).setOnCancelListener(new DialogInterfaceOnCancelListenerC2236jm(this, dVar, 1));
        builderJ.create().show();
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) throws IllegalAccessException, Resources.NotFoundException, InstantiationException, IllegalArgumentException, InvocationTargetException {
        switch (i) {
            case 1:
                Intent intent = (Intent) AbstractC2857y5.a(parcel, Intent.CREATOR);
                AbstractC2857y5.b(parcel);
                l0(intent);
                break;
            case 2:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                String string = parcel.readString();
                String string2 = parcel.readString();
                AbstractC2857y5.b(parcel);
                J3(aVarV3, new zza(string, string2, ""));
                break;
            case 3:
                g();
                break;
            case 4:
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                Q1(aVarV32);
                break;
            case 5:
                String[] strArrCreateStringArray = parcel.createStringArray();
                int[] iArrCreateIntArray = parcel.createIntArray();
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                r1(strArrCreateStringArray, iArrCreateIntArray, aVarV33);
                break;
            case 6:
                com.google.android.gms.dynamic.a aVarV34 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zza zzaVar = (zza) AbstractC2857y5.a(parcel, zza.CREATOR);
                AbstractC2857y5.b(parcel);
                J3(aVarV34, zzaVar);
                break;
            default:
                return false;
        }
        parcel2.writeNoException();
        return true;
    }

    public final void f4(String str, Yi yi) {
        InterfaceC2860y8 interfaceC2860y8;
        String strP = yi.p();
        String strB = yi.b();
        String string = "";
        if (TextUtils.isEmpty(strP)) {
            strP = strB != null ? strB : "";
        }
        InterfaceC2860y8 interfaceC2860y8K = yi.k();
        if (interfaceC2860y8K != null) {
            try {
                string = interfaceC2860y8K.zze().toString();
            } catch (RemoteException unused) {
            }
        }
        synchronized (yi) {
            interfaceC2860y8 = yi.s;
        }
        Drawable drawable = null;
        if (interfaceC2860y8 != null) {
            try {
                com.google.android.gms.dynamic.a aVarF = interfaceC2860y8.f();
                if (aVarF != null) {
                    drawable = (Drawable) com.google.android.gms.dynamic.b.I3(aVarF);
                }
            } catch (RemoteException unused2) {
            }
        }
        this.a.put(str, new C2019em(strP, string, drawable));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    public final void g() {
        this.e.d(new S4(this.d, 21));
    }

    public final void i4(String str, String str2, Map map) {
        e4(this.b, this.c, this.e, str, str2, map);
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:24:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void j4() throws java.lang.IllegalAccessException, java.lang.InstantiationException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            r7 = this;
            com.google.android.gms.ads.internal.j r0 = com.google.android.gms.ads.internal.j.C     // Catch: android.os.RemoteException -> L22
            com.google.android.gms.ads.internal.util.F r0 = r0.c     // Catch: android.os.RemoteException -> L22
            android.content.Context r0 = r7.b     // Catch: android.os.RemoteException -> L22
            com.google.android.gms.ads.internal.util.s r1 = com.google.android.gms.ads.internal.util.F.a(r0)     // Catch: android.os.RemoteException -> L22
            com.google.android.gms.dynamic.b r2 = new com.google.android.gms.dynamic.b     // Catch: android.os.RemoteException -> L22
            r2.<init>(r0)     // Catch: android.os.RemoteException -> L22
            com.google.android.gms.ads.internal.offline.buffering.zza r3 = new com.google.android.gms.ads.internal.offline.buffering.zza     // Catch: android.os.RemoteException -> L22
            java.lang.String r4 = r7.g     // Catch: android.os.RemoteException -> L22
            java.lang.String r5 = r7.f     // Catch: android.os.RemoteException -> L22
            java.util.HashMap r6 = r7.a     // Catch: android.os.RemoteException -> L22
            java.lang.Object r6 = r6.get(r5)     // Catch: android.os.RemoteException -> L22
            com.google.android.gms.internal.ads.em r6 = (com.google.android.gms.internal.ads.C2019em) r6     // Catch: android.os.RemoteException -> L22
            if (r6 != 0) goto L24
            java.lang.String r6 = ""
            goto L26
        L22:
            r0 = move-exception
            goto L41
        L24:
            java.lang.String r6 = r6.b     // Catch: android.os.RemoteException -> L22
        L26:
            r3.<init>(r4, r5, r6)     // Catch: android.os.RemoteException -> L22
            boolean r2 = r1.zzg(r2, r3)     // Catch: android.os.RemoteException -> L22
            if (r2 != 0) goto L3f
            com.google.android.gms.dynamic.b r3 = new com.google.android.gms.dynamic.b     // Catch: android.os.RemoteException -> L3d
            r3.<init>(r0)     // Catch: android.os.RemoteException -> L3d
            java.lang.String r0 = r7.g     // Catch: android.os.RemoteException -> L3d
            java.lang.String r4 = r7.f     // Catch: android.os.RemoteException -> L3d
            boolean r0 = r1.zzf(r3, r0, r4)     // Catch: android.os.RemoteException -> L3d
            goto L48
        L3d:
            r0 = move-exception
            goto L42
        L3f:
            r0 = 1
            goto L48
        L41:
            r2 = 0
        L42:
            java.lang.String r1 = "Failed to schedule offline notification poster."
            com.google.android.gms.ads.internal.util.client.i.f(r1, r0)
            r0 = r2
        L48:
            if (r0 != 0) goto L5a
            com.google.android.gms.internal.ads.gm r0 = r7.e
            java.lang.String r1 = r7.f
            r0.a(r1)
            java.lang.String r0 = r7.f
            com.google.android.gms.internal.ads.Gu r1 = com.google.android.gms.internal.ads.Gu.g
            java.lang.String r2 = "offline_notification_worker_not_scheduled"
            r7.i4(r0, r2, r1)
        L5a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.BinderC2408nm.j4():void");
    }

    public final void k4(Activity activity, com.google.android.gms.ads.internal.overlay.d dVar) throws IllegalAccessException, Resources.NotFoundException, InstantiationException, IllegalArgumentException, InvocationTargetException {
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        if (NotificationManagerCompat.from(activity).areNotificationsEnabled()) {
            j4();
            l4(activity, dVar);
            return;
        }
        int i = Build.VERSION.SDK_INT;
        Gu gu = Gu.g;
        if (i >= 33) {
            activity.requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 12345);
            i4(this.f, "asnpdi", gu);
        } else {
            AlertDialog.Builder builderJ = com.google.android.gms.ads.internal.util.F.j(activity);
            builderJ.setTitle(h4(R.string.notifications_permission_title, "Allow app to send you notifications?")).setPositiveButton(h4(R.string.notifications_permission_confirm, "Allow"), new DialogInterfaceOnClickListenerC2151hm(this, activity, dVar, 0)).setNegativeButton(h4(R.string.notifications_permission_decline, "Don't allow"), new DialogInterfaceOnClickListenerC2194im(0, this, dVar)).setOnCancelListener(new DialogInterfaceOnCancelListenerC2236jm(this, dVar, 0));
            builderJ.create().show();
            i4(this.f, "rtsdi", gu);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    public final void l0(Intent intent) {
        C2107gm c2107gm = this.e;
        String stringExtra = intent.getStringExtra("offline_notification_action");
        if (stringExtra != null) {
            if (stringExtra.equals("offline_notification_clicked") || stringExtra.equals("offline_notification_dismissed")) {
                String stringExtra2 = intent.getStringExtra("gws_query_id");
                String stringExtra3 = intent.getStringExtra("uri");
                C2010ed c2010ed = com.google.android.gms.ads.internal.j.C.h;
                Context context = this.b;
                boolean zA = c2010ed.a(context);
                HashMap map = new HashMap();
                if (stringExtra.equals("offline_notification_clicked")) {
                    map.put("offline_notification_action", "offline_notification_clicked");
                    c = true == zA ? (char) 1 : (char) 2;
                    map.put("obvs", String.valueOf(Build.VERSION.SDK_INT));
                    map.put("olaih", String.valueOf(stringExtra3.startsWith("http")));
                    try {
                        Intent launchIntentForPackage = context.getPackageManager().getLaunchIntentForPackage(stringExtra3);
                        if (launchIntentForPackage == null) {
                            launchIntentForPackage = new Intent("android.intent.action.VIEW");
                            launchIntentForPackage.setData(Uri.parse(stringExtra3));
                        }
                        launchIntentForPackage.addFlags(268435456);
                        context.startActivity(launchIntentForPackage);
                        map.put("olaa", "olas");
                    } catch (ActivityNotFoundException unused) {
                        map.put("olaa", "olaf");
                    }
                } else {
                    map.put("offline_notification_action", "offline_notification_dismissed");
                }
                i4(stringExtra2, "offline_notification_action", map);
                try {
                    SQLiteDatabase writableDatabase = c2107gm.getWritableDatabase();
                    if (c == 1) {
                        c2107gm.b.execute(new C(writableDatabase, stringExtra2, this.d, 7));
                    } else {
                        writableDatabase.delete("offline_buffered_pings", "gws_query_id = ? AND event_state = ?", new String[]{stringExtra2, Integer.toString(0)});
                    }
                } catch (SQLiteException e) {
                    com.google.android.gms.ads.internal.util.client.i.e("Failed to get writable offline buffering database: ".concat(e.toString()));
                }
            }
        }
    }

    public final void l4(Activity activity, com.google.android.gms.ads.internal.overlay.d dVar) throws Resources.NotFoundException {
        XmlResourceParser layout;
        AlertDialog alertDialogCreate;
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        com.google.android.gms.ads.internal.util.F f = jVar.c;
        AlertDialog.Builder onCancelListener = com.google.android.gms.ads.internal.util.F.j(activity).setOnCancelListener(new DialogInterfaceOnCancelListenerC2357me(dVar, 2));
        Resources resourcesB = jVar.h.b();
        if (resourcesB == null) {
            layout = null;
        } else {
            try {
                layout = resourcesB.getLayout(R.layout.offline_ads_dialog);
            } catch (Resources.NotFoundException unused) {
            }
        }
        if (layout == null) {
            onCancelListener.setMessage(h4(R.string.offline_dialog_text, "Thanks for your interest.\nWe will share more once you're back online."));
            alertDialogCreate = onCancelListener.create();
        } else {
            try {
                View viewInflate = activity.getLayoutInflater().inflate(layout, (ViewGroup) null);
                onCancelListener.setView(viewInflate);
                HashMap map = this.a;
                C2019em c2019em = (C2019em) map.get(this.f);
                String str = c2019em == null ? "" : c2019em.a;
                if (!TextUtils.isEmpty(str)) {
                    TextView textView = (TextView) viewInflate.findViewById(R.id.offline_dialog_advertiser_name);
                    textView.setVisibility(0);
                    textView.setText(str);
                }
                C2019em c2019em2 = (C2019em) map.get(this.f);
                Drawable drawable = c2019em2 != null ? c2019em2.c : null;
                if (drawable != null) {
                    ((ImageView) viewInflate.findViewById(R.id.offline_dialog_image)).setImageDrawable(drawable);
                }
                alertDialogCreate = onCancelListener.create();
                alertDialogCreate.getWindow().setBackgroundDrawable(new ColorDrawable(0));
            } catch (Resources.NotFoundException unused2) {
                onCancelListener.setMessage(h4(R.string.offline_dialog_text, "Thanks for your interest.\nWe will share more once you're back online."));
                alertDialogCreate = onCancelListener.create();
            }
        }
        alertDialogCreate.show();
        Timer timer = new Timer();
        timer.schedule(new C2365mm(alertDialogCreate, timer, dVar), 3000L);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    public final void r1(String[] strArr, int[] iArr, com.google.android.gms.dynamic.a aVar) throws IllegalAccessException, Resources.NotFoundException, InstantiationException, IllegalArgumentException, InvocationTargetException {
        for (int i = 0; i < strArr.length; i++) {
            if (strArr[i].equals("android.permission.POST_NOTIFICATIONS")) {
                C2063fm c2063fm = (C2063fm) com.google.android.gms.dynamic.b.I3(aVar);
                Activity activity = c2063fm.a;
                HashMap map = new HashMap();
                int i2 = iArr[i];
                com.google.android.gms.ads.internal.overlay.d dVar = c2063fm.b;
                if (i2 == 0) {
                    map.put("dialog_action", "confirm");
                    j4();
                    l4(activity, dVar);
                } else {
                    map.put("dialog_action", "dismiss");
                    if (dVar != null) {
                        dVar.b();
                    }
                }
                i4(this.f, "asnpdc", map);
                return;
            }
        }
    }
}
