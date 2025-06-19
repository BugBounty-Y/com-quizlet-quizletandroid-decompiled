package androidx.work;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class CoroutineWorker extends y {
    public final WorkerParameters e;
    public final C1426g f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CoroutineWorker(@NotNull Context appContext, @NotNull WorkerParameters params) {
        super(appContext, params);
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        Intrinsics.checkNotNullParameter(params, "params");
        this.e = params;
        this.f = C1426g.b;
    }

    public abstract Object a(kotlin.coroutines.h hVar);

    public AbstractC5040y b() {
        return this.f;
    }

    @Override // androidx.work.y
    public final com.google.common.util.concurrent.e getForegroundInfoAsync() {
        return AbstractC3394t2.i(b().plus(kotlinx.coroutines.E.d()), new C1427h(this, null));
    }

    @Override // androidx.work.y
    public final com.google.common.util.concurrent.e startWork() {
        AbstractC5040y abstractC5040yB = !Intrinsics.b(b(), C1426g.b) ? b() : this.e.g;
        Intrinsics.checkNotNullExpressionValue(abstractC5040yB, "if (coroutineContext != …rkerContext\n            }");
        return AbstractC3394t2.i(abstractC5040yB.plus(kotlinx.coroutines.E.d()), new C1428i(this, null));
    }
}
