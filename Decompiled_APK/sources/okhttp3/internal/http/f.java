package okhttp3.internal.http;

import androidx.compose.material.ripple.r;
import androidx.constraintlayout.core.motion.utils.l;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.C;
import okhttp3.H;
import okhttp3.internal.connection.g;
import okhttp3.t;
import okhttp3.u;

/* loaded from: classes3.dex */
public final class f implements t {
    public final g a;
    public final ArrayList b;
    public final int c;
    public final r d;
    public final C e;
    public final int f;
    public final int g;
    public final int h;
    public int i;

    public f(g call, ArrayList interceptors, int i, r rVar, C request, int i2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(interceptors, "interceptors");
        Intrinsics.checkNotNullParameter(request, "request");
        this.a = call;
        this.b = interceptors;
        this.c = i;
        this.d = rVar;
        this.e = request;
        this.f = i2;
        this.g = i3;
        this.h = i4;
    }

    public static f a(f fVar, int i, r rVar, C c, int i2, int i3, int i4, int i5) {
        if ((i5 & 1) != 0) {
            i = fVar.c;
        }
        int i6 = i;
        if ((i5 & 2) != 0) {
            rVar = fVar.d;
        }
        r rVar2 = rVar;
        if ((i5 & 4) != 0) {
            c = fVar.e;
        }
        C request = c;
        if ((i5 & 8) != 0) {
            i2 = fVar.f;
        }
        int i7 = i2;
        if ((i5 & 16) != 0) {
            i3 = fVar.g;
        }
        int i8 = i3;
        int i9 = (i5 & 32) != 0 ? fVar.h : i4;
        fVar.getClass();
        Intrinsics.checkNotNullParameter(request, "request");
        return new f(fVar.a, fVar.b, i6, rVar2, request, i7, i8, i9);
    }

    public final H b(C request) {
        Intrinsics.checkNotNullParameter(request, "request");
        ArrayList arrayList = this.b;
        int size = arrayList.size();
        int i = this.c;
        if (i >= size) {
            throw new IllegalStateException("Check failed.");
        }
        this.i++;
        r rVar = this.d;
        if (rVar != null) {
            if (!((l) rVar.c).e(request.a)) {
                throw new IllegalStateException(("network interceptor " + arrayList.get(i - 1) + " must retain the same host and port").toString());
            }
            if (this.i != 1) {
                throw new IllegalStateException(("network interceptor " + arrayList.get(i - 1) + " must call proceed() exactly once").toString());
            }
        }
        int i2 = i + 1;
        f fVarA = a(this, i2, null, request, 0, 0, 0, 58);
        u uVar = (u) arrayList.get(i);
        H hIntercept = uVar.intercept(fVarA);
        if (hIntercept == null) {
            throw new NullPointerException("interceptor " + uVar + " returned null");
        }
        if (rVar != null && i2 < arrayList.size() && fVarA.i != 1) {
            throw new IllegalStateException(("network interceptor " + uVar + " must call proceed() exactly once").toString());
        }
        if (hIntercept.g != null) {
            return hIntercept;
        }
        throw new IllegalStateException(("interceptor " + uVar + " returned a response with no body").toString());
    }
}
