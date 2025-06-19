package androidx.compose.ui.scrollcapture;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ float k;
    public final /* synthetic */ f l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        e eVar = new e(this.l, hVar);
        eVar.k = ((Number) obj).floatValue();
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create(Float.valueOf(((Number) obj).floatValue()), (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            float f = this.k;
            f fVar = this.l;
            Object obj2 = fVar.a.d.a.get(androidx.compose.ui.semantics.j.e);
            if (obj2 == null) {
                obj2 = null;
            }
            Function2 function2 = (Function2) obj2;
            if (function2 == null) {
                W4.g("Required value was null.");
                throw null;
            }
            androidx.compose.ui.geometry.b bVar = new androidx.compose.ui.geometry.b(Q4.c(DefinitionKt.NO_Float_VALUE, f));
            this.j = 1;
            obj = function2.invoke(bVar, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return new Float(androidx.compose.ui.geometry.b.e(((androidx.compose.ui.geometry.b) obj).a));
    }
}
