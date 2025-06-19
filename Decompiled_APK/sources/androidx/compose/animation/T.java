package androidx.compose.animation;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class T extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(androidx.camera.camera2.internal.p0 p0Var, boolean z) {
        super(1);
        this.a = 2;
        this.c = p0Var;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                ((androidx.compose.ui.graphics.S) obj).e(!this.b && ((Boolean) ((Function0) this.c).invoke()).booleanValue());
                break;
            case 1:
                ((androidx.compose.ui.graphics.S) obj).b(this.b ? 1.0f : ((Number) ((Function0) this.c).invoke()).floatValue());
                break;
            default:
                kotlinx.serialization.json.g Json = (kotlinx.serialization.json.g) obj;
                Intrinsics.checkNotNullParameter(Json, "$this$Json");
                androidx.camera.camera2.internal.p0 p0Var = (androidx.camera.camera2.internal.p0) this.c;
                Json.getClass();
                Intrinsics.checkNotNullParameter(p0Var, "<set-?>");
                Json.k = p0Var;
                Json.c = true;
                Json.d = true;
                Json.j = true;
                Json.a = true;
                Json.b = this.b;
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ T(boolean z, Function0 function0, int i) {
        super(1);
        this.a = i;
        this.b = z;
        this.c = function0;
    }
}
