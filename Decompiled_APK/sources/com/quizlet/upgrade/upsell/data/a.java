package com.quizlet.upgrade.upsell.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;
import com.quizlet.qutils.string.f;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a d;
    public static final /* synthetic */ a[] e;
    public final f a;
    public final f b;
    public final c c;

    static {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        f fVar = new f(R.string.upsell_expert_solutions_title, C4933y.P(args));
        Object[] args2 = new Object[0];
        Intrinsics.checkNotNullParameter(args2, "args");
        a aVar = new a(fVar, new f(R.string.upsell_expert_solutions_subtitle, C4933y.P(args2)), new c(new b(R.drawable.ic_brand_textbooks_plus, R.string.upsell_expert_solutions_verified_textbooks_value_prop), new b(R.drawable.ic_brand_solutions_plus, R.string.upsell_expert_solutions_verified_solutions_value_prop), new b(R.drawable.ic_brand_step_by_step_plus, R.string.upsell_expert_solutions_step_by_step_value_prop)));
        d = aVar;
        a[] aVarArr = {aVar};
        e = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public a(f fVar, f fVar2, c cVar) {
        this.a = fVar;
        this.b = fVar2;
        this.c = cVar;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) e.clone();
    }
}
