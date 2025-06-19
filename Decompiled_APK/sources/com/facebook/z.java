package com.facebook;

import android.content.SharedPreferences;
import androidx.compose.animation.d0;
import com.quizlet.generated.enums.G1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class z {
    public final SharedPreferences a;

    public z(SharedPreferences sharedPreferences, int i) {
        switch (i) {
            case 2:
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                this.a = sharedPreferences;
                break;
            default:
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                this.a = sharedPreferences;
                break;
        }
    }

    public static String b(long j, G1 g1) {
        if (g1 == G1.SET) {
            return d0.n(j, "inSelectedTermsMode--");
        }
        return "inSelectedTermsMode-" + g1 + "-" + j;
    }

    public boolean a(long j, G1 studyableType) {
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        return this.a.getBoolean(b(j, studyableType), false);
    }

    public void c(long j, G1 studyableType, boolean z) {
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        this.a.edit().putBoolean(b(j, studyableType), z).apply();
    }

    public z() {
        SharedPreferences sharedPreferences = o.a().getSharedPreferences("com.facebook.AccessTokenManager.SharedPreferences", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getApplicationContext()\n…ME, Context.MODE_PRIVATE)");
        this.a = sharedPreferences;
    }
}
