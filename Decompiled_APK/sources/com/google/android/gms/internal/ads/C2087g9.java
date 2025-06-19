package com.google.android.gms.internal.ads;

import android.os.SystemClock;
import android.text.TextUtils;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.ads.g9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2087g9 implements InterfaceC2389n9 {
    public static final Pattern a = Pattern.compile("^[a-zA-Z]([a-zA-Z0-9]|:|-|_)*$");
    public static final Pattern b = Pattern.compile("^[0-9]*(,[0-9]*)*$");

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) throws NumberFormatException {
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
        String str = (String) map.get("action");
        boolean zEquals = "tick".equals(str);
        Pattern pattern = a;
        if (!zEquals) {
            if ("experiment".equals(str)) {
                String str2 = (String) map.get("value");
                if (TextUtils.isEmpty(str2)) {
                    com.google.android.gms.ads.internal.util.client.i.h("No value given for CSI experiment.");
                    return;
                }
                if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.d2)).booleanValue() || b.matcher(str2).matches()) {
                    ((B7) interfaceC2529qe.k().c).b("e", str2);
                    return;
                } else {
                    com.google.android.gms.ads.internal.util.client.i.d("Invalid value given for CSI experiment. Should be a comma separated list of numbers.");
                    return;
                }
            }
            if ("extra".equals(str)) {
                String str3 = (String) map.get("name");
                String str4 = (String) map.get("value");
                if (TextUtils.isEmpty(str4)) {
                    com.google.android.gms.ads.internal.util.client.i.h("No value given for CSI extra.");
                    return;
                }
                if (TextUtils.isEmpty(str3)) {
                    com.google.android.gms.ads.internal.util.client.i.h("No name given for CSI extra.");
                    return;
                }
                if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.d2)).booleanValue() || pattern.matcher(str3).matches()) {
                    ((B7) interfaceC2529qe.k().c).b(str3, str4);
                    return;
                } else {
                    com.google.android.gms.ads.internal.util.client.i.d("Invalid name given for CSI extra. Should start with a letter and only alphanumerics, :, -, _ are allowed.");
                    return;
                }
            }
            return;
        }
        String str5 = (String) map.get("label");
        String str6 = (String) map.get("start_label");
        String str7 = (String) map.get("timestamp");
        if (TextUtils.isEmpty(str5)) {
            com.google.android.gms.ads.internal.util.client.i.h("No label given for CSI tick.");
            return;
        }
        C2601s7 c2601s7 = AbstractC2773w7.d2;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && !pattern.matcher(str5).matches()) {
            com.google.android.gms.ads.internal.util.client.i.d("Invalid label given for CSI tick. Should start with a letter and only alphanumerics, :, -, _ are allowed.");
            return;
        }
        if (TextUtils.isEmpty(str7)) {
            com.google.android.gms.ads.internal.util.client.i.h("No timestamp given for CSI tick.");
            return;
        }
        try {
            long j = Long.parseLong(str7);
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            jVar.k.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            jVar.k.getClass();
            long jElapsedRealtime = (j - jCurrentTimeMillis) + SystemClock.elapsedRealtime();
            if (true == TextUtils.isEmpty(str6)) {
                str6 = "native:view_load";
            }
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && !pattern.matcher(str6).matches()) {
                com.google.android.gms.ads.internal.util.client.i.d("Invalid start label given for CSI tick. Should start with a letter and only alphanumerics, :, -, _ are allowed.");
                return;
            }
            C1732Mb c1732MbK = interfaceC2529qe.k();
            HashMap map2 = (HashMap) c1732MbK.b;
            C2902z7 c2902z7 = (C2902z7) map2.get(str6);
            String[] strArr = {str5};
            if (c2902z7 != null) {
                ((B7) c1732MbK.c).c(c2902z7, jElapsedRealtime, strArr);
            }
            map2.put(str5, new C2902z7(jElapsedRealtime, null, null));
        } catch (NumberFormatException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Malformed timestamp for CSI tick.", e);
        }
    }
}
