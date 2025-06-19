package androidx.glance.appwidget;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.y7;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import kotlin.Unit;

/* renamed from: androidx.glance.appwidget.n0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1185n0 {
    public static final C1221y g = new C1221y();
    public final Context a;
    public final LinkedHashMap b;
    public int c;
    public final int d;
    public final LinkedHashSet e;
    public final LinkedHashSet f;

    public C1185n0(Context context, LinkedHashMap linkedHashMap, int i, int i2, LinkedHashSet linkedHashSet) {
        LinkedHashSet linkedHashSet2 = new LinkedHashSet();
        this.a = context;
        this.b = linkedHashMap;
        this.c = i;
        this.d = i2;
        this.e = linkedHashSet2;
        this.f = linkedHashSet;
    }

    public final int a(androidx.glance.k kVar) {
        androidx.glance.appwidget.proto.i iVarA = y7.a(kVar);
        synchronized (this) {
            Integer num = (Integer) this.b.get(iVarA);
            if (num != null) {
                int iIntValue = num.intValue();
                this.e.add(Integer.valueOf(iIntValue));
                return iIntValue;
            }
            int i = this.c;
            while (this.f.contains(Integer.valueOf(i))) {
                i = (i + 1) % r0.c;
                if (i == this.c) {
                    throw new IllegalArgumentException("Cannot assign a valid layout index to the new layout: no free index left.");
                }
            }
            this.c = (i + 1) % r0.c;
            this.e.add(Integer.valueOf(i));
            this.f.add(Integer.valueOf(i));
            this.b.put(iVarA, Integer.valueOf(i));
            return i;
        }
    }

    public final Object b(C1172h c1172h) {
        Object objD = androidx.glance.state.f.a.d(this.a, t0.a, "appWidgetLayout-" + this.d, new C1183m0(this, null), c1172h);
        return objD == kotlin.coroutines.intrinsics.a.a ? objD : Unit.a;
    }
}
