package com.quizlet.explanations.textbook.exercisedetail.recyclerview.header;

import com.quizlet.data.model.X;
import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes2.dex */
public abstract class d implements com.quizlet.baserecyclerview.a {
    public final u a;
    public final long b = -1;
    public final u c;

    public d() {
        final int i = 0;
        this.a = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.a
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        d dVar = this.b;
                        return Boolean.valueOf(dVar.h() && !dVar.g());
                    default:
                        Object[] args = {this.b.b()};
                        Intrinsics.checkNotNullParameter(args, "args");
                        return new com.quizlet.qutils.string.f(R.string.exercise_name, C4933y.P(args));
                }
            }
        });
        final int i2 = 1;
        this.c = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.a
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        d dVar = this.b;
                        return Boolean.valueOf(dVar.h() && !dVar.g());
                    default:
                        Object[] args = {this.b.b()};
                        Intrinsics.checkNotNullParameter(args, "args");
                        return new com.quizlet.qutils.string.f(R.string.exercise_name, C4933y.P(args));
                }
            }
        });
    }

    public abstract X a();

    public abstract String b();

    public abstract String c();

    public abstract String d();

    public abstract String e();

    public abstract boolean f();

    public abstract boolean g();

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Long.valueOf(this.b);
    }

    public abstract boolean h();
}
