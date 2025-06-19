package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.ads.Pa, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1749Pa implements com.google.android.gms.ads.mediation.n {
    public final HashSet a;
    public final boolean b;
    public final int c;
    public final zzbfv d;
    public final boolean f;
    public final ArrayList e = new ArrayList();
    public final HashMap g = new HashMap();

    public C1749Pa(HashSet hashSet, boolean z, int i, zzbfv zzbfvVar, ArrayList arrayList, boolean z2) {
        this.a = hashSet;
        this.b = z;
        this.c = i;
        this.d = zzbfvVar;
        this.f = z2;
        if (arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                String str = (String) it2.next();
                if (str.startsWith("custom:")) {
                    String[] strArrSplit = str.split(":", 3);
                    if (strArrSplit.length == 3) {
                        if ("true".equals(strArrSplit[2])) {
                            this.g.put(strArrSplit[1], Boolean.TRUE);
                        } else if ("false".equals(strArrSplit[2])) {
                            this.g.put(strArrSplit[1], Boolean.FALSE);
                        }
                    }
                } else {
                    this.e.add(str);
                }
            }
        }
    }

    @Override // com.google.android.gms.ads.mediation.d
    public final int a() {
        return this.c;
    }

    @Override // com.google.android.gms.ads.mediation.d
    public final boolean b() {
        return this.f;
    }

    @Override // com.google.android.gms.ads.mediation.d
    public final boolean c() {
        return this.b;
    }

    @Override // com.google.android.gms.ads.mediation.d
    public final Set d() {
        return this.a;
    }
}
