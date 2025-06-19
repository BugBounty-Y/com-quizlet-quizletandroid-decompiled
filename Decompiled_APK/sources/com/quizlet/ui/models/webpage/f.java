package com.quizlet.ui.models.webpage;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.net.URLEncoder;

/* loaded from: classes3.dex */
public abstract class f extends m {
    public final String a;

    public f(String str) {
        this.a = str;
    }

    @Override // com.quizlet.ui.models.webpage.m
    public final String b() {
        return AbstractC0147y.d("https://quizlet.com/oauthweb/redirect?redir=", URLEncoder.encode(this.a, "UTF-8"));
    }
}
