package com.quizlet.api;

import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public interface IHttpErrorManager {

    @Metadata
    public static final class HttpErrorManager implements IHttpErrorManager {
        public static final HttpErrorManager a = new HttpErrorManager();

        @Override // com.quizlet.api.IHttpErrorManager
        public final boolean a(int i) {
            return HttpStatusRangeConstants.c.a(Integer.valueOf(i));
        }

        @Override // com.quizlet.api.IHttpErrorManager
        public final boolean b(int i) {
            return HttpStatusRangeConstants.b.a(Integer.valueOf(i));
        }
    }

    boolean a(int i);

    boolean b(int i);
}
