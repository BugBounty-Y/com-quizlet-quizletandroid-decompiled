package com.google.android.gms.internal.ads;

import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.f1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2035f1 implements InterfaceC2856y4 {
    public final ArrayList a;

    public C2035f1(ArrayList arrayList) {
        this.a = arrayList;
        boolean z = false;
        if (!arrayList.isEmpty()) {
            long j = ((C1991e1) arrayList.get(0)).b;
            int i = 1;
            while (true) {
                if (i >= arrayList.size()) {
                    break;
                }
                if (((C1991e1) arrayList.get(i)).a < j) {
                    z = true;
                    break;
                } else {
                    j = ((C1991e1) arrayList.get(i)).b;
                    i++;
                }
            }
        }
        AbstractC1795We.B(!z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2856y4
    public final /* synthetic */ void a(L3 l3) {
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2035f1.class != obj.getClass()) {
            return false;
        }
        return this.a.equals(((C2035f1) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SlowMotion: segments=".concat(this.a.toString());
    }
}
