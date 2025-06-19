package com.quizlet.features.practicetest.navigation;

import androidx.navigation.C1290l;
import androidx.navigation.S;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements com.quizlet.ui.compose.navigation.b {
    public final String a;
    public final String b;
    public final String c;

    public i(String str, String str2, String str3) {
        this.a = str;
        this.b = str2;
        this.c = str3;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        final int i = 0;
        final int i2 = 1;
        final int i3 = 2;
        return B.j(D1.b("questionBankUuid", new Function1(this) { // from class: com.quizlet.features.practicetest.navigation.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.b);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.c);
                        break;
                }
                return Unit.a;
            }
        }), D1.b("navigationOrigin", new Function1(this) { // from class: com.quizlet.features.practicetest.navigation.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i2) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.b);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.c);
                        break;
                }
                return Unit.a;
            }
        }), D1.b("practiceTestId", new Function1(this) { // from class: com.quizlet.features.practicetest.navigation.h
            public final /* synthetic */ i b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                C1290l navArgument = (C1290l) obj;
                switch (i3) {
                    case 0:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.a);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.b);
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.a.a = true;
                        navArgument.b(S.n);
                        navArgument.a(this.b.c);
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
        return "takingTest";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return Intrinsics.b(this.a, iVar.a) && Intrinsics.b(this.b, iVar.b) && Intrinsics.b(this.c, iVar.c);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.c;
        return iHashCode2 + (str3 != null ? str3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TakingTest(questionBankUuid=");
        sb.append(this.a);
        sb.append(", navigationOrigin=");
        sb.append(this.b);
        sb.append(", practiceTestUuid=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
