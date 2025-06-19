package com.quizlet.db.data.orm;

import androidx.core.util.c;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class RequestParameters {
    public final ArrayList a = new ArrayList();

    public final void a(String str, String str2) {
        this.a.add(new c(str, str2));
    }

    public List<c> getKeyValuePairs() {
        return this.a;
    }
}
