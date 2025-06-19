package com.google.firebase.sessions;

import android.os.Message;
import java.util.Comparator;

/* loaded from: classes2.dex */
public final class a0 implements Comparator {
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        return kotlin.comparisons.a.b(Long.valueOf(((Message) obj).getWhen()), Long.valueOf(((Message) obj2).getWhen()));
    }
}
