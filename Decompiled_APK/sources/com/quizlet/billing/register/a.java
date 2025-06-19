package com.quizlet.billing.register;

import android.content.SharedPreferences;
import androidx.compose.animation.d0;
import assistantMode.enums.m;
import com.quizlet.features.infra.basestudy.helper.b;
import com.quizlet.features.infra.models.flashcards.c;
import com.quizlet.features.infra.models.flashcards.d;
import com.quizlet.generated.enums.G1;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final SharedPreferences a;

    public a(SharedPreferences preferences, int i) {
        switch (i) {
            case 1:
                this.a = preferences;
                break;
            default:
                Intrinsics.checkNotNullParameter(preferences, "preferences");
                this.a = preferences;
                break;
        }
    }

    public static m b(int i) {
        return i != 1 ? i != 2 ? m.b : m.d : m.c;
    }

    public static String c(long j, G1 g1, String str) {
        if (g1 == G1.SET) {
            return j + ":" + str;
        }
        return g1 + "-" + j + ":" + str;
    }

    public b a(long j, G1 g1) {
        Boolean boolValueOf;
        String strC = c(j, g1, "flashCardFrontSide");
        SharedPreferences sharedPreferences = this.a;
        int i = sharedPreferences.getInt(strC, -1);
        int i2 = sharedPreferences.getInt(c(j, g1, "flashCardBackSide"), -1);
        long j2 = -1;
        long j3 = sharedPreferences.getLong(d0.n(j, "flashcards-shuffle-seed-"), j2);
        int i3 = sharedPreferences.getInt(c(j, g1, "rawFlashcardMode"), -1);
        sharedPreferences.edit().remove(c(j, g1, "flashCardFrontSide")).remove(c(j, g1, "flashCardBackSide")).remove("flashcards-shuffle-seed-" + j).remove(c(j, g1, "rawFlashcardMode")).apply();
        m mVarB = i == -1 ? null : b(i);
        m mVarB2 = i2 == -1 ? null : b(i2);
        if (i3 != -1) {
            c.b.getClass();
            c[] cVarArrValues = c.values();
            int length = cVarArrValues.length;
            for (int i4 = 0; i4 < length; i4++) {
                c cVar = cVarArrValues[i4];
                if (cVar.a == i3) {
                    boolValueOf = Boolean.valueOf(cVar == c.c);
                }
            }
            throw new NoSuchElementException("Array contains no element matching the predicate.");
        }
        boolValueOf = null;
        return new b(mVarB, mVarB2, boolValueOf, j3 != j2 ? Long.valueOf(j3) : null);
    }

    public boolean d(long j) {
        String string = this.a.getString("register_" + j, "");
        return !(string == null || string.length() == 0);
    }

    public void e(long j, G1 g1, d dVar) {
        this.a.edit().putBoolean(c(j, g1, "flashCardSpeakWord"), dVar.c).putBoolean(c(j, g1, "flashCardSpeakDefinition"), dVar.d).putBoolean(c(j, g1, "flashCardPlay"), dVar.e).putBoolean(c(j, g1, "flashCardShuffle"), dVar.f).apply();
    }
}
