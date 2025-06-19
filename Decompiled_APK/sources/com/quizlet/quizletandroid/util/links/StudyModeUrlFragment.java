package com.quizlet.quizletandroid.util.links;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Arrays;
import java.util.HashSet;

@Retention(RetentionPolicy.SOURCE)
/* loaded from: classes3.dex */
public @interface StudyModeUrlFragment {
    public static final HashSet a = new HashSet(Arrays.asList("blast", "blocks", "cards", "classic-cards", "flashcards", "learn", "match", "microscatter", "scatter", "test", "write"));
}
