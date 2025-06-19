package com.google.firebase.components;

import java.util.Set;

/* loaded from: classes2.dex */
public interface b {
    com.google.firebase.inject.b a(q qVar);

    default com.google.firebase.inject.b b(Class cls) {
        return a(q.a(cls));
    }

    default Set c(q qVar) {
        return (Set) e(qVar).get();
    }

    com.google.firebase.inject.b e(q qVar);

    default Object f(q qVar) {
        com.google.firebase.inject.b bVarA = a(qVar);
        if (bVarA == null) {
            return null;
        }
        return bVarA.get();
    }

    o g(q qVar);

    default Object get(Class cls) {
        return f(q.a(cls));
    }
}
