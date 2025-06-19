package com.braze.storage;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public interface ICardStorageProvider<T> {
    void markCardAsClicked(String str);

    void markCardAsDismissed(String str);

    void markCardAsViewed(String str);

    void markCardAsVisuallyRead(String str);
}
