package com.quizlet.quizletandroid.ui.preview.adapter;

import androidx.recyclerview.widget.AbstractC1358c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends AbstractC1358c {
    public static final a d = new a();

    @Override // androidx.recyclerview.widget.AbstractC1358c
    public final boolean a(Object obj, Object obj2) {
        com.quizlet.quizletandroid.ui.preview.dataclass.a oldItem = (com.quizlet.quizletandroid.ui.preview.dataclass.a) obj;
        com.quizlet.quizletandroid.ui.preview.dataclass.a newItem = (com.quizlet.quizletandroid.ui.preview.dataclass.a) obj2;
        Intrinsics.checkNotNullParameter(oldItem, "oldItem");
        Intrinsics.checkNotNullParameter(newItem, "newItem");
        return oldItem.equals(newItem);
    }

    @Override // androidx.recyclerview.widget.AbstractC1358c
    public final boolean b(Object obj, Object obj2) {
        com.quizlet.quizletandroid.ui.preview.dataclass.a oldItem = (com.quizlet.quizletandroid.ui.preview.dataclass.a) obj;
        com.quizlet.quizletandroid.ui.preview.dataclass.a newItem = (com.quizlet.quizletandroid.ui.preview.dataclass.a) obj2;
        Intrinsics.checkNotNullParameter(oldItem, "oldItem");
        Intrinsics.checkNotNullParameter(newItem, "newItem");
        return oldItem.a == newItem.a;
    }
}
