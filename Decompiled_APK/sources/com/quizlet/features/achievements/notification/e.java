package com.quizlet.features.achievements.notification;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.data.model.AbstractC4152o;
import com.quizlet.data.model.C4114c;
import com.quizlet.data.model.C4143l;
import com.quizlet.data.model.C4146m;
import com.quizlet.data.model.C4149n;
import com.quizlet.data.model.EnumC4110b;
import com.quizlet.features.achievements.achievement.g;
import com.quizlet.generated.enums.EnumC4485h;
import java.util.Locale;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objU;
        EnumC4110b enumC4110bValueOf;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        f fVar = this.k;
        if (i == 0) {
            Z.e(obj);
            q qVar = fVar.b;
            this.j = 1;
            objU = qVar.u(this);
            if (objU == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objU = obj;
        }
        AbstractC4152o abstractC4152o = (AbstractC4152o) objU;
        if (abstractC4152o instanceof C4143l) {
            C4143l c4143l = (C4143l) abstractC4152o;
            fVar.getClass();
            EnumC4485h data = c4143l.b;
            Intrinsics.checkNotNullParameter(data, "data");
            if (B.j(EnumC4485h.BADGE, EnumC4485h.STREAK, EnumC4485h.DAILY_STUDY_STREAK, EnumC4485h.DAILY_STUDY_STREAK_BADGE, EnumC4485h.WEEKLY_STUDY_STREAK, EnumC4485h.WEEKLY_STUDY_STREAK_BADGE, EnumC4485h.SETS_STUDIED_BADGE, EnumC4485h.STUDIED_WITH_FLASHCARDS_BADGE, EnumC4485h.STUDIED_WITH_LEARN_BADGE, EnumC4485h.ROUNDS_STUDIED_BADGE, EnumC4485h.REACHED_END_OF_LEARN_BADGE, EnumC4485h.STUDIED_WITH_MATCH_BADGE, EnumC4485h.NIGHT_OWL_BADGE, EnumC4485h.EARLY_BIRD_BADGE, EnumC4485h.STUDIED_WITH_TEST_BADGE, EnumC4485h.CREATED_FIRST_SET_BADGE, EnumC4485h.FIRST_HIGHSCORE_IN_MATCH_BADGE).contains(data)) {
                EnumC4485h enumC4485h = c4143l.b;
                String strA = enumC4485h.a();
                String str = c4143l.i;
                if (str != null) {
                    String upperCase = str.toUpperCase(Locale.ROOT);
                    Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
                    enumC4110bValueOf = EnumC4110b.valueOf(upperCase);
                } else {
                    enumC4110bValueOf = null;
                }
                C4114c c4114c = new C4114c(strA, c4143l.d, true, c4143l.e, c4143l.f, c4143l.g, enumC4110bValueOf, null);
                String upperCase2 = c4143l.h.toUpperCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(upperCase2, "toUpperCase(...)");
                fVar.f.j(new a(new com.quizlet.features.achievements.achievement.a(enumC4485h, c4114c, g.valueOf(upperCase2))));
                E.A(p0.j(fVar), null, null, new d(fVar, null), 3);
            }
        } else {
            if (!(abstractC4152o instanceof C4146m) && !Intrinsics.b(abstractC4152o, C4149n.a)) {
                throw new NoWhenBranchMatchedException();
            }
            fVar.f.j(b.a);
        }
        return Unit.a;
    }
}
