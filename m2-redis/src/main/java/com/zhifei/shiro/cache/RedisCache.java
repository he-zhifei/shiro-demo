package com.zhifei.shiro.cache;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Component
public class RedisCache<K, V> implements Cache<K, V> {

    @Resource(name = "objectRedisTemplate")
    private RedisTemplate redisTemplate;

    /**
     * Redis中shiro缓存前缀
     */
    private static final String SHIRO_CACHE_PREFIX = "shiro-cache-prefix:";

    /**
     * Redis中shiro缓存过期时间（秒）
     */
    private static final int CACHE_EXPIRE_TIME = 600;

    private K getKey(K k) {
        if (k instanceof String) {
            return (K) (SHIRO_CACHE_PREFIX + (String) k);
        }
        return k;
    }

    @Override
    public V get(K k) throws CacheException {
        Object obj = redisTemplate.opsForValue().get(getKey(k));
        if (obj != null) {
            return (V) obj;
        }
        return null;
    }

    @Override
    public V put(K k, V v) throws CacheException {
        redisTemplate.opsForValue().set(getKey(k), v, CACHE_EXPIRE_TIME, TimeUnit.SECONDS);
        return v;
    }

    @Override
    public V remove(K k) throws CacheException {
        V v = get(getKey(k));
        if (v != null) redisTemplate.delete(v);
        return v;
    }

    // 注意：这个方法不用重写 ，因为redis中可能存在其他与shiro不相干的数据
    @Override
    public void clear() throws CacheException {}

    @Override
    public int size() {
        return 0;
    }

    @Override
    public Set<K> keys() {
        return null;
    }

    @Override
    public Collection<V> values() {
        return null;
    }
}
