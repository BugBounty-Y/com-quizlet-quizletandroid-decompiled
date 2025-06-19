package com.quizlet.login.common.navigation;

import android.content.Intent;
import androidx.navigation.C1290l;
import androidx.navigation.O;
import androidx.navigation.S;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements com.quizlet.ui.compose.navigation.b {
    public final boolean a;
    public final String b;
    public final Intent c;

    public h(boolean z, String str, Intent originIntent) {
        Intrinsics.checkNotNullParameter(originIntent, "originIntent");
        this.a = z;
        this.b = str;
        this.c = originIntent;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        final int i = 0;
        final int i2 = 1;
        final int i3 = 2;
        return B.j(D1.b("intent", new Function1(this) { // from class: com.quizlet.login.common.navigation.g
            public final /* synthetic */ h b;

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
                        navArgument.b(new O(Intent.class));
                        navArgument.a(this.b.c);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a.a = false;
                        navArgument.a(Boolean.valueOf(this.b.a));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = true;
                        navArgument.a(this.b.b);
                        break;
                }
                return Unit.a;
            }
        }), D1.b("shouldKillApp", new Function1(this) { // from class: com.quizlet.login.common.navigation.g
            public final /* synthetic */ h b;

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
                        navArgument.b(new O(Intent.class));
                        navArgument.a(this.b.c);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a.a = false;
                        navArgument.a(Boolean.valueOf(this.b.a));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = true;
                        navArgument.a(this.b.b);
                        break;
                }
                return Unit.a;
            }
        }), D1.b("magicLinkCode", new Function1(this) { // from class: com.quizlet.login.common.navigation.g
            public final /* synthetic */ h b;

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
                        navArgument.b(new O(Intent.class));
                        navArgument.a(this.b.c);
                        break;
                    case 1:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.k);
                        navArgument.a.a = false;
                        navArgument.a(Boolean.valueOf(this.b.a));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                        navArgument.b(S.n);
                        navArgument.a.a = true;
                        navArgument.a(this.b.b);
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
        return "intro";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a == hVar.a && Intrinsics.b(this.b, hVar.b) && Intrinsics.b(this.c, hVar.c);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        String str = this.b;
        return this.c.hashCode() + ((iHashCode + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        return "Intro(shouldKillApp=" + this.a + ", magicLinkCode=" + this.b + ", originIntent=" + this.c + ")";
    }
}
