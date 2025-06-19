package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation;

import androidx.navigation.C1287i;
import androidx.navigation.C1290l;
import androidx.navigation.O;
import androidx.navigation.S;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.quizletandroid.ui.login.z;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsIntentData;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements com.quizlet.ui.compose.navigation.b {
    public final LearnSettingsIntentData a;

    public d(LearnSettingsIntentData learnSettingsIntentData) {
        Intrinsics.checkNotNullParameter(learnSettingsIntentData, "learnSettingsIntentData");
        this.a = learnSettingsIntentData;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        final int i = 0;
        C1287i c1287iB = D1.b("studySessionId", new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.c
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.e);
                        navArgument.a.a = false;
                        navArgument.a(Long.valueOf(this.b.a.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.b);
                        navArgument.a.a = false;
                        navArgument.a(Integer.valueOf(this.b.a.f));
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.e);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a.a = false;
                        navArgument.a(Boolean.valueOf(this.b.a.d));
                        break;
                }
                return Unit.a;
            }
        });
        final int i2 = 1;
        C1287i c1287iB2 = D1.b("studyableModelData", new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.c
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i2) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.e);
                        navArgument.a.a = false;
                        navArgument.a(Long.valueOf(this.b.a.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.b);
                        navArgument.a.a = false;
                        navArgument.a(Integer.valueOf(this.b.a.f));
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.e);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a.a = false;
                        navArgument.a(Boolean.valueOf(this.b.a.d));
                        break;
                }
                return Unit.a;
            }
        });
        final int i3 = 2;
        C1287i c1287iB3 = D1.b("studyableModelLocalId", new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.c
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i3) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.e);
                        navArgument.a.a = false;
                        navArgument.a(Long.valueOf(this.b.a.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.b);
                        navArgument.a.a = false;
                        navArgument.a(Integer.valueOf(this.b.a.f));
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.e);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a.a = false;
                        navArgument.a(Boolean.valueOf(this.b.a.d));
                        break;
                }
                return Unit.a;
            }
        });
        final int i4 = 3;
        C1287i c1287iB4 = D1.b("navigationSource", new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.c
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i4) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.e);
                        navArgument.a.a = false;
                        navArgument.a(Long.valueOf(this.b.a.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.b);
                        navArgument.a.a = false;
                        navArgument.a(Integer.valueOf(this.b.a.f));
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.e);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a.a = false;
                        navArgument.a(Boolean.valueOf(this.b.a.d));
                        break;
                }
                return Unit.a;
            }
        });
        final int i5 = 4;
        final int i6 = 5;
        return B.j(c1287iB, c1287iB2, c1287iB3, c1287iB4, D1.b("screen_name_key", new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.c
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i5) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.e);
                        navArgument.a.a = false;
                        navArgument.a(Long.valueOf(this.b.a.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.b);
                        navArgument.a.a = false;
                        navArgument.a(Integer.valueOf(this.b.a.f));
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.e);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a.a = false;
                        navArgument.a(Boolean.valueOf(this.b.a.d));
                        break;
                }
                return Unit.a;
            }
        }), D1.b("study_mode_type_key", new z(15)), D1.b("selectedOnlyIntent", new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.c
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i6) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(new O(StudyableModelData.class));
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.b);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.e);
                        navArgument.a.a = false;
                        navArgument.a(Long.valueOf(this.b.a.c));
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.b);
                        navArgument.a.a = false;
                        navArgument.a(Integer.valueOf(this.b.a.f));
                        break;
                    case 4:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = false;
                        navArgument.a(this.b.a.e);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a.a = false;
                        navArgument.a(Boolean.valueOf(this.b.a.d));
                        break;
                }
                return Unit.a;
            }
        }));
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "learn_settings";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "LearnSettings(learnSettingsIntentData=" + this.a + ")";
    }
}
