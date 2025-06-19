package com.quizlet.features.folders.composables;

import com.quizlet.generated.enums.M0;

/* renamed from: com.quizlet.features.folders.composables.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract /* synthetic */ class AbstractC4260p {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[M0.values().length];
        try {
            iArr[M0.NONE.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            iArr[M0.TEXTBOOK_LLM.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            iArr[M0.PEER_ACTIVITY.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            iArr[M0.KNOWLEDGE_GRAPH_ML.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            iArr[M0.TEXTBOOK_SME.ordinal()] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            iArr[M0.KNOWLEDGE_GRAPH_SME.ordinal()] = 6;
        } catch (NoSuchFieldError unused6) {
        }
        a = iArr;
    }
}
