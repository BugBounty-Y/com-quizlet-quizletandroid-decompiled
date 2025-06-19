package com.quizlet.eventlogger.features.search;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes2.dex */
public final class SearchType {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ SearchType[] $VALUES;
    public static final SearchType a;
    public static final SearchType b;
    public static final SearchType c;
    public static final SearchType d;
    public static final SearchType e;
    public static final SearchType f;

    static {
        SearchType searchType = new SearchType("ALL", 0);
        a = searchType;
        SearchType searchType2 = new SearchType("SET", 1);
        b = searchType2;
        SearchType searchType3 = new SearchType("CLASS", 2);
        c = searchType3;
        SearchType searchType4 = new SearchType("USER", 3);
        d = searchType4;
        SearchType searchType5 = new SearchType("QUESTION", 4);
        e = searchType5;
        SearchType searchType6 = new SearchType("TEXTBOOK", 5);
        f = searchType6;
        SearchType[] searchTypeArr = {searchType, searchType2, searchType3, searchType4, searchType5, searchType6};
        $VALUES = searchTypeArr;
        $ENTRIES = AbstractC3328d.f(searchTypeArr);
    }

    private SearchType(String str, int i) {
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static SearchType valueOf(String str) {
        return (SearchType) Enum.valueOf(SearchType.class, str);
    }

    public static SearchType[] values() {
        return (SearchType[]) $VALUES.clone();
    }
}
