package com.quizlet.quizletandroid.ui.activitycenter.fragments;

import com.braze.ui.contentcards.ContentCardsFragment;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public abstract class DaggerContentCardsFragment extends ContentCardsFragment implements dagger.android.c {
    public C4636c a;

    @Override // dagger.android.c
    public final C4636c c() {
        C4636c c4636c = this.a;
        if (c4636c != null) {
            return c4636c;
        }
        Intrinsics.m("androidInjector");
        throw null;
    }
}
