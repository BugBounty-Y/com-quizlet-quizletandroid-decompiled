package com.quizlet.studiablemodels;

import android.os.Parcelable;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public abstract class StudiableStep implements Parcelable {
    public StudiableMeteringData a;

    public StudiableStep(StudiableMeteringData studiableMeteringData) {
        this.a = studiableMeteringData;
    }
}
