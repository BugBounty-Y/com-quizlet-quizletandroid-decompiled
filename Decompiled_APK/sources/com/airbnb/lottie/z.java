package com.airbnb.lottie;

import java.util.Arrays;

/* loaded from: classes.dex */
public final class z {
    public final h a;
    public final Throwable b;

    public z(h hVar) {
        this.a = hVar;
        this.b = null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        h hVar = this.a;
        if (hVar != null && hVar.equals(zVar.a)) {
            return true;
        }
        Throwable th = this.b;
        if (th == null || zVar.b == null) {
            return false;
        }
        return th.toString().equals(th.toString());
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b});
    }

    public z(Throwable th) {
        this.b = th;
        this.a = null;
    }
}
