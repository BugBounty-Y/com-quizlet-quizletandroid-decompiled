package com.quizlet.search.data;

import android.os.Parcelable;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public abstract class SearchFilterState<T> implements Parcelable {
    public final Enum a;

    public SearchFilterState(Enum r1) {
        this.a = r1;
    }
}
