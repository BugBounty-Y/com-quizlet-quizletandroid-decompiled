package androidx.camera.view;

import android.graphics.Bitmap;
import android.graphics.RectF;
import android.util.Size;
import android.view.Display;
import android.view.TextureView;
import android.view.View;
import android.widget.FrameLayout;
import androidx.camera.camera2.internal.T;
import androidx.camera.core.j0;
import androidx.work.C1425f;
import androidx.work.C1437k;
import androidx.work.EnumC1420a;
import androidx.work.J;
import androidx.work.N;
import androidx.work.Q;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.measurement.T1;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.UUID;
import kotlin.collections.CollectionsKt;
import kotlin.collections.a0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.I;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes.dex */
public abstract class j {
    public boolean a;
    public Object b;
    public Object c;
    public final Object d;

    public j(FrameLayout frameLayout, c cVar) {
        this.a = false;
        this.c = frameLayout;
        this.d = cVar;
    }

    public Q a() {
        Q qB = b();
        C1425f c1425f = ((androidx.work.impl.model.q) this.c).j;
        boolean z = c1425f.a() || c1425f.e || c1425f.c || c1425f.d;
        androidx.work.impl.model.q qVar = (androidx.work.impl.model.q) this.c;
        if (qVar.q) {
            if (z) {
                throw new IllegalArgumentException("Expedited jobs only support network and storage constraints");
            }
            if (qVar.g > 0) {
                throw new IllegalArgumentException("Expedited jobs cannot be delayed");
            }
        }
        if (qVar.x == null) {
            List listSplit$default = StringsKt__StringsKt.split$default(qVar.c, new String[]{"."}, false, 0, 6, null);
            String strC = listSplit$default.size() == 1 ? (String) listSplit$default.get(0) : (String) CollectionsKt.U(listSplit$default);
            if (strC.length() > 127) {
                strC = I.C(127, strC);
            }
            qVar.x = strC;
        }
        UUID id = UUID.randomUUID();
        Intrinsics.checkNotNullExpressionValue(id, "randomUUID()");
        Intrinsics.checkNotNullParameter(id, "id");
        this.b = id;
        String newId = id.toString();
        Intrinsics.checkNotNullExpressionValue(newId, "id.toString()");
        androidx.work.impl.model.q other = (androidx.work.impl.model.q) this.c;
        Intrinsics.checkNotNullParameter(newId, "newId");
        Intrinsics.checkNotNullParameter(other, "other");
        this.c = new androidx.work.impl.model.q(newId, other.b, other.c, other.d, new C1437k(other.e), new C1437k(other.f), other.g, other.h, other.i, new C1425f(other.j), other.k, other.l, other.m, other.n, other.o, other.p, other.q, other.r, other.s, other.u, other.v, other.w, other.x, 524288);
        return qB;
    }

    public abstract Q b();

    public abstract View c();

    public abstract Bitmap d();

    public abstract j e();

    public abstract void f();

    public abstract void g();

    public abstract void h(j0 j0Var, T t);

    public void i() {
        View viewC = c();
        if (viewC == null || !this.a) {
            return;
        }
        FrameLayout frameLayout = (FrameLayout) this.c;
        Size size = new Size(frameLayout.getWidth(), frameLayout.getHeight());
        int layoutDirection = frameLayout.getLayoutDirection();
        c cVar = (c) this.d;
        cVar.getClass();
        if (size.getHeight() == 0 || size.getWidth() == 0) {
            AbstractC3053s1.h("PreviewTransform", "Transform not applied due to PreviewView size: " + size);
            return;
        }
        if (cVar.f()) {
            if (viewC instanceof TextureView) {
                ((TextureView) viewC).setTransform(cVar.d());
            } else {
                Display display = viewC.getDisplay();
                boolean z = false;
                boolean z2 = (!cVar.g || display == null || display.getRotation() == cVar.e) ? false : true;
                boolean z3 = cVar.g;
                if (!z3) {
                    if ((!z3 ? cVar.c : -T1.b(cVar.e)) != 0) {
                        z = true;
                    }
                }
                if (z2 || z) {
                    AbstractC3053s1.c("PreviewTransform", "Custom rotation not supported with SurfaceView/PERFORMANCE mode.");
                }
            }
            RectF rectFE = cVar.e(size, layoutDirection);
            viewC.setPivotX(DefinitionKt.NO_Float_VALUE);
            viewC.setPivotY(DefinitionKt.NO_Float_VALUE);
            viewC.setScaleX(rectFE.width() / cVar.a.getWidth());
            viewC.setScaleY(rectFE.height() / cVar.a.getHeight());
            viewC.setTranslationX(rectFE.left - viewC.getLeft());
            viewC.setTranslationY(rectFE.top - viewC.getTop());
        }
    }

    public j j(C1425f constraints) {
        Intrinsics.checkNotNullParameter(constraints, "constraints");
        ((androidx.work.impl.model.q) this.c).j = constraints;
        return e();
    }

    public j k(C1437k inputData) {
        Intrinsics.checkNotNullParameter(inputData, "inputData");
        ((androidx.work.impl.model.q) this.c).e = inputData;
        return e();
    }

    public abstract com.google.common.util.concurrent.e l();

    public j(Class workerClass) {
        Intrinsics.checkNotNullParameter(workerClass, "workerClass");
        UUID uuidRandomUUID = UUID.randomUUID();
        Intrinsics.checkNotNullExpressionValue(uuidRandomUUID, "randomUUID()");
        this.b = uuidRandomUUID;
        String id = ((UUID) this.b).toString();
        Intrinsics.checkNotNullExpressionValue(id, "id.toString()");
        String workerClassName_ = workerClass.getName();
        Intrinsics.checkNotNullExpressionValue(workerClassName_, "workerClass.name");
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(workerClassName_, "workerClassName_");
        this.c = new androidx.work.impl.model.q(id, (N) null, workerClassName_, (String) null, (C1437k) null, (C1437k) null, 0L, 0L, 0L, (C1425f) null, 0, (EnumC1420a) null, 0L, 0L, 0L, 0L, false, (J) null, 0, 0L, 0, 0, (String) null, 16777210);
        String name = workerClass.getName();
        Intrinsics.checkNotNullExpressionValue(name, "workerClass.name");
        this.d = a0.d(name);
    }
}
