package com.quizlet.features.flashcards.navigation;

import androidx.compose.animation.d0;
import androidx.navigation.C1287i;
import androidx.navigation.C1290l;
import androidx.navigation.O;
import androidx.navigation.S;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f implements com.quizlet.ui.compose.navigation.b {
    public final int a;
    public final StudyableModelData b;
    public final long c;
    public final String d;
    public final boolean e;
    public final String f;
    public final List g;

    public f(int i, long j, StudyableModelData studyableModelData, String title, String screenName, boolean z) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        this.a = i;
        this.b = studyableModelData;
        this.c = j;
        this.d = title;
        this.e = z;
        this.f = screenName;
        final int i2 = 0;
        C1287i c1287iB = D1.b("navigationSource", new Function1(this) { // from class: com.quizlet.features.flashcards.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i2) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.b);
                        navArgument.a(Integer.valueOf(this.b.a));
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.e);
                        navArgument.a(Long.valueOf(this.b.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.f);
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.e));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        });
        final int i3 = 1;
        C1287i c1287iB2 = D1.b("studyableModelData", new Function1(this) { // from class: com.quizlet.features.flashcards.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i3) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.b);
                        navArgument.a(Integer.valueOf(this.b.a));
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.e);
                        navArgument.a(Long.valueOf(this.b.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.f);
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.e));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        });
        final int i4 = 2;
        C1287i c1287iB3 = D1.b("studyableModelLocalId", new Function1(this) { // from class: com.quizlet.features.flashcards.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i4) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.b);
                        navArgument.a(Integer.valueOf(this.b.a));
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.e);
                        navArgument.a(Long.valueOf(this.b.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.f);
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.e));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        });
        final int i5 = 3;
        C1287i c1287iB4 = D1.b("screen_name_key", new Function1(this) { // from class: com.quizlet.features.flashcards.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i5) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.b);
                        navArgument.a(Integer.valueOf(this.b.a));
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.e);
                        navArgument.a(Long.valueOf(this.b.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.f);
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.e));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        });
        final int i6 = 4;
        C1287i c1287iB5 = D1.b("selectedOnlyIntent", new Function1(this) { // from class: com.quizlet.features.flashcards.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i6) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.b);
                        navArgument.a(Integer.valueOf(this.b.a));
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.e);
                        navArgument.a(Long.valueOf(this.b.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.f);
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.e));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        });
        final int i7 = 5;
        this.g = B.j(c1287iB, c1287iB2, c1287iB3, c1287iB4, c1287iB5, D1.b("studyableModelTitle", new Function1(this) { // from class: com.quizlet.features.flashcards.navigation.e
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i7) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.b);
                        navArgument.a(Integer.valueOf(this.b.a));
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a(this.b.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.e);
                        navArgument.a(Long.valueOf(this.b.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.f);
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.k);
                        navArgument.a(Boolean.valueOf(this.b.e));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = false;
                        navArgument.b(S.n);
                        navArgument.a(this.b.d);
                        break;
                }
                return Unit.a;
            }
        }), D1.b("study_mode_type_key", new C4237k(3)));
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return this.g;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "flashcards";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b) && this.c == fVar.c && Intrinsics.b(this.d, fVar.d) && this.e == fVar.e && Intrinsics.b(this.f, fVar.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + d0.g(d0.e(d0.d((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31, 31, this.c), 31, this.d), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Flashcards(navigationSource=");
        sb.append(this.a);
        sb.append(", studyableModelData=");
        sb.append(this.b);
        sb.append(", localId=");
        sb.append(this.c);
        sb.append(", title=");
        sb.append(this.d);
        sb.append(", selectedTermsOnly=");
        sb.append(this.e);
        sb.append(", screenName=");
        return android.support.v4.media.session.a.t(sb, this.f, ")");
    }
}
