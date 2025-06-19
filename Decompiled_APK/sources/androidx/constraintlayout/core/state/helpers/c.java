package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.compose.k;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashMap;

/* loaded from: classes.dex */
public abstract class c extends androidx.constraintlayout.core.state.g {
    public float n0;
    public final HashMap o0;
    public final HashMap p0;
    public final HashMap q0;
    public HashMap r0;
    public HashMap s0;
    public androidx.constraintlayout.core.state.i t0;

    public c(k kVar, int i) {
        super(kVar, i);
        this.n0 = 0.5f;
        this.o0 = new HashMap();
        this.p0 = new HashMap();
        this.q0 = new HashMap();
        this.t0 = androidx.constraintlayout.core.state.i.a;
    }

    public final float t(String str) {
        HashMap map = this.s0;
        return (map == null || !map.containsKey(str)) ? DefinitionKt.NO_Float_VALUE : ((Float) this.s0.get(str)).floatValue();
    }

    public final float u(String str) {
        HashMap map = this.q0;
        return map.containsKey(str) ? ((Float) map.get(str)).floatValue() : DefinitionKt.NO_Float_VALUE;
    }

    public final float v(String str) {
        HashMap map = this.r0;
        return (map == null || !map.containsKey(str)) ? DefinitionKt.NO_Float_VALUE : ((Float) this.r0.get(str)).floatValue();
    }

    public final float w(String str) {
        HashMap map = this.p0;
        return map.containsKey(str) ? ((Float) map.get(str)).floatValue() : DefinitionKt.NO_Float_VALUE;
    }
}
