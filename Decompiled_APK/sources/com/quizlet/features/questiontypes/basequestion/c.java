package com.quizlet.features.questiontypes.basequestion;

import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;

/* loaded from: classes3.dex */
public final class c {
    public static final List a = B.j(Integer.valueOf(R.string.answer_label_success_01), Integer.valueOf(R.string.answer_label_success_02), Integer.valueOf(R.string.answer_label_success_03), Integer.valueOf(R.string.answer_label_success_04), Integer.valueOf(R.string.answer_label_success_05));
    public static final List b = B.j(Integer.valueOf(R.string.answer_label_error_01), Integer.valueOf(R.string.answer_label_error_02), Integer.valueOf(R.string.answer_label_error_03));
    public static final List c = B.j(Integer.valueOf(R.string.answer_label_correct_retry_01), Integer.valueOf(R.string.answer_label_correct_retry_02), Integer.valueOf(R.string.answer_label_correct_retry_03));

    public static int a(boolean z) {
        return z ? ((Number) CollectionsKt.f0(c, kotlin.random.e.a)).intValue() : ((Number) CollectionsKt.f0(a, kotlin.random.e.a)).intValue();
    }

    public static int b() {
        return ((Number) CollectionsKt.f0(b, kotlin.random.e.a)).intValue();
    }
}
