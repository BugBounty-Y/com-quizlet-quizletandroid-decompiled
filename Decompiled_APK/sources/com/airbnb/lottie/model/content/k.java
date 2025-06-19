package com.airbnb.lottie.model.content;

import android.graphics.PointF;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class k {
    public final ArrayList a;
    public PointF b;
    public boolean c;

    public k(PointF pointF, boolean z, List list) {
        this.b = pointF;
        this.c = z;
        this.a = new ArrayList(list);
    }

    public final void a(float f, float f2) {
        if (this.b == null) {
            this.b = new PointF();
        }
        this.b.set(f, f2);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ShapeData{numCurves=");
        sb.append(this.a.size());
        sb.append("closed=");
        return android.support.v4.media.session.a.u(sb, this.c, '}');
    }

    public k() {
        this.a = new ArrayList();
    }
}
