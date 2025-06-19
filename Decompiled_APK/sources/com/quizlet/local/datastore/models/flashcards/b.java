package com.quizlet.local.datastore.models.flashcards;

import com.google.android.gms.internal.mlkit_vision_barcode.J6;
import kotlin.jvm.internal.B;
import kotlin.jvm.internal.K;
import kotlin.reflect.n;

/* loaded from: classes3.dex */
public abstract class b {
    public static final /* synthetic */ n[] a;
    public static final androidx.datastore.b b;

    static {
        B b2 = new B(b.class, "flashcardsPreferencesDataStore", "getFlashcardsPreferencesDataStore(Landroid/content/Context;)Landroidx/datastore/core/DataStore;", 1);
        K.a.getClass();
        a = new n[]{b2};
        b = J6.b("flashcardsPreferences.pb", a.a, new com.airbnb.lottie.network.c(new com.quizlet.features.universaluploadflow.flashcards.d(21)));
    }
}
