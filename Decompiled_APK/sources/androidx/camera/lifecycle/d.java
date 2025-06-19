package androidx.camera.lifecycle;

import android.content.Context;
import androidx.camera.core.C0194q;
import com.google.android.gms.internal.mlkit_common.s;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Context b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(Context context, int i) {
        super(1);
        this.a = i;
        this.b = context;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                C0194q cameraX = (C0194q) obj;
                g gVar = g.i;
                Intrinsics.checkNotNullExpressionValue(cameraX, "cameraX");
                gVar.f = cameraX;
                Context contextB = s.b(this.b);
                Intrinsics.checkNotNullExpressionValue(contextB, "getApplicationContext(context)");
                gVar.g = contextB;
                return gVar;
            case 1:
                Context it2 = (Context) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return new androidx.privacysandbox.ads.adservices.measurement.b(this.b);
            case 2:
                Context it3 = (Context) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return new androidx.privacysandbox.ads.adservices.topics.c(this.b);
            default:
                Context it4 = (Context) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                return new androidx.privacysandbox.ads.adservices.topics.d(this.b);
        }
    }
}
