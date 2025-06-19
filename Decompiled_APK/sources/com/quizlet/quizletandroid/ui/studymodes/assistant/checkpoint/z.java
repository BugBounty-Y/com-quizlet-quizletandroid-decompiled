package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import androidx.recyclerview.widget.AbstractC1358c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z extends AbstractC1358c {
    public static final z d = new z();

    @Override // androidx.recyclerview.widget.AbstractC1358c
    public final boolean a(Object obj, Object obj2) {
        com.quizlet.learn.checkpoint.data.d oldItem = (com.quizlet.learn.checkpoint.data.d) obj;
        com.quizlet.learn.checkpoint.data.d newItem = (com.quizlet.learn.checkpoint.data.d) obj2;
        Intrinsics.checkNotNullParameter(oldItem, "oldItem");
        Intrinsics.checkNotNullParameter(newItem, "newItem");
        return oldItem.equals(newItem);
    }

    @Override // androidx.recyclerview.widget.AbstractC1358c
    public final boolean b(Object obj, Object obj2) {
        com.quizlet.learn.checkpoint.data.d oldItem = (com.quizlet.learn.checkpoint.data.d) obj;
        com.quizlet.learn.checkpoint.data.d newItem = (com.quizlet.learn.checkpoint.data.d) obj2;
        Intrinsics.checkNotNullParameter(oldItem, "oldItem");
        Intrinsics.checkNotNullParameter(newItem, "newItem");
        return oldItem.a.a == newItem.a.a;
    }
}
