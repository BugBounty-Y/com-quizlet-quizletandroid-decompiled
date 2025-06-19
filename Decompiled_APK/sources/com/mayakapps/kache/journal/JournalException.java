package com.mayakapps.kache.journal;

import java.io.IOException;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public abstract class JournalException extends IOException {
    public final String a;

    public JournalException(String str) {
        super(str);
        this.a = str;
    }

    @Override // java.lang.Throwable
    public String getMessage() {
        return this.a;
    }
}
