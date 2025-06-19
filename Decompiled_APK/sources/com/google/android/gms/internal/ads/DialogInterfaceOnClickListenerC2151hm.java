package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.app.DownloadManager;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Resources;
import android.net.Uri;
import android.os.Environment;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import org.json.JSONException;

/* renamed from: com.google.android.gms.internal.ads.hm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class DialogInterfaceOnClickListenerC2151hm implements DialogInterface.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public DialogInterfaceOnClickListenerC2151hm(C2483pb c2483pb, String str, String str2) {
        this.a = 2;
        this.b = str;
        this.c = str2;
        this.d = c2483pb;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) throws JSONException, IllegalAccessException, Resources.NotFoundException, InstantiationException, IllegalArgumentException, InvocationTargetException {
        switch (this.a) {
            case 0:
                HashMap map = new HashMap();
                map.put("dialog_action", "confirm");
                BinderC2408nm binderC2408nm = (BinderC2408nm) this.b;
                binderC2408nm.i4(binderC2408nm.f, "rtsdc", map);
                com.google.android.gms.ads.internal.j.C.f.getClass();
                Intent intent = new Intent();
                intent.setAction("android.settings.APP_NOTIFICATION_SETTINGS");
                Activity activity = (Activity) this.c;
                intent.putExtra("android.provider.extra.APP_PACKAGE", activity.getPackageName());
                activity.startActivity(intent);
                binderC2408nm.j4();
                com.google.android.gms.ads.internal.overlay.d dVar = (com.google.android.gms.ads.internal.overlay.d) this.d;
                if (dVar != null) {
                    dVar.b();
                    break;
                }
                break;
            case 1:
                HashMap map2 = new HashMap();
                map2.put("dialog_action", "confirm");
                BinderC2408nm binderC2408nm2 = (BinderC2408nm) this.b;
                binderC2408nm2.i4(binderC2408nm2.f, "dialog_click", map2);
                binderC2408nm2.k4((Activity) this.c, (com.google.android.gms.ads.internal.overlay.d) this.d);
                break;
            default:
                C2483pb c2483pb = (C2483pb) this.d;
                DownloadManager downloadManager = (DownloadManager) c2483pb.d.getSystemService("download");
                try {
                    String str = (String) this.b;
                    String str2 = (String) this.c;
                    DownloadManager.Request request = new DownloadManager.Request(Uri.parse(str));
                    request.setDestinationInExternalPublicDir(Environment.DIRECTORY_PICTURES, str2);
                    com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                    request.allowScanningByMediaScanner();
                    request.setNotificationVisibility(1);
                    downloadManager.enqueue(request);
                    break;
                } catch (IllegalStateException unused) {
                    c2483pb.u("Could not store picture.");
                }
        }
    }

    public /* synthetic */ DialogInterfaceOnClickListenerC2151hm(BinderC2408nm binderC2408nm, Activity activity, com.google.android.gms.ads.internal.overlay.d dVar, int i) {
        this.a = i;
        this.b = binderC2408nm;
        this.c = activity;
        this.d = dVar;
    }
}
