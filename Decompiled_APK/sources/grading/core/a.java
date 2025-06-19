package grading.core;

import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a {
    public final r a;
    public final grading.core.enums.a b;
    public final Function2 c;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public a(String str, androidx.compose.foundation.lazy.grid.h transform, int i) {
        this(grading.core.utils.a.a, (grading.core.enums.a) null, transform);
        Intrinsics.checkNotNullParameter(transform, "transform");
    }

    public final boolean a(h submissionContext) {
        Intrinsics.checkNotNullParameter(submissionContext, "submissionContext");
        grading.core.enums.a setting = this.b;
        if (setting == null) {
            return true;
        }
        Intrinsics.checkNotNullParameter(setting, "setting");
        d dVar = submissionContext.d;
        dVar.getClass();
        Intrinsics.checkNotNullParameter(setting, "setting");
        int iOrdinal = setting.ordinal();
        if (iOrdinal == 0) {
            return dVar.a;
        }
        if (iOrdinal == 1) {
            return dVar.b;
        }
        if (iOrdinal == 2) {
            return dVar.c;
        }
        if (iOrdinal == 3) {
            return dVar.d;
        }
        throw new NoWhenBranchMatchedException();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public a(String str, Function1 transformFunction) {
        this(grading.core.utils.a.a, (grading.core.enums.a) null, new androidx.compose.foundation.lazy.grid.h(1, transformFunction));
        Intrinsics.checkNotNullParameter(transformFunction, "transformFunction");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public a(kotlin.jvm.functions.c condition, grading.core.enums.a aVar, Function2 transform) {
        Intrinsics.checkNotNullParameter(condition, "condition");
        Intrinsics.checkNotNullParameter(transform, "transform");
        this.a = (r) condition;
        this.b = aVar;
        this.c = transform;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public a(kotlin.jvm.functions.c condition, grading.core.enums.a aVar, Function1 transformFunction) {
        this(condition, aVar, new androidx.compose.foundation.lazy.grid.h(1, transformFunction));
        Intrinsics.checkNotNullParameter(condition, "condition");
        Intrinsics.checkNotNullParameter(transformFunction, "transformFunction");
    }
}
