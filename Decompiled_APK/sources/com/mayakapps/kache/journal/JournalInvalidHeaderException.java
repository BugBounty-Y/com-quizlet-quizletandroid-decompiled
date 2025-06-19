package com.mayakapps.kache.journal;

import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class JournalInvalidHeaderException extends JournalException {
    public final String b;

    public JournalInvalidHeaderException() {
        this(null);
    }

    @Override // com.mayakapps.kache.journal.JournalException, java.lang.Throwable
    public final String getMessage() {
        return this.b;
    }

    public JournalInvalidHeaderException(String str) {
        super(str);
        this.b = str;
    }
}
