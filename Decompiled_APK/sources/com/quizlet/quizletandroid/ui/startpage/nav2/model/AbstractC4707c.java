package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import kotlin.NoWhenBranchMatchedException;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4707c implements com.quizlet.baserecyclerview.a {
    public boolean a;
    public int b = -1;
    public int c = -1;

    public String d() {
        return null;
    }

    public String e() {
        return null;
    }

    public final int f() {
        if (!(this instanceof C)) {
            return -1;
        }
        C c = (C) this;
        if (c instanceof x) {
            return 0;
        }
        if (c instanceof D) {
            return ((D) this).f;
        }
        if (c instanceof w) {
            return 0;
        }
        throw new NoWhenBranchMatchedException();
    }
}
