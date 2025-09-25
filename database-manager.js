// Database Manager for Supabase Integration
class DatabaseManager {
  constructor(supabaseClient) {
    this.supabase = supabaseClient;
  }

  // Scan History Management
  async saveScanResult(scanData) {
    try {
      const { data, error } = await this.supabase
        .from('scan_history')
        .insert({
          user_id: 'anonymous',
          scan_type: scanData.type,
          target_name: scanData.name,
          target_hash: scanData.hash,
          file_size: scanData.size,
          mime_type: scanData.mimeType,
          scan_status: 'completed',
          total_engines: scanData.totalEngines,
          malicious_count: scanData.stats.malicious,
          suspicious_count: scanData.stats.suspicious,
          harmless_count: scanData.stats.harmless,
          undetected_count: scanData.stats.undetected,
          scan_results: scanData,
          virustotal_scan_id: scanData.scanId,
          virustotal_permalink: scanData.permalink,
          scanned_at: new Date().toISOString()
        });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Failed to save scan result:', error);
      throw error;
    }
  }

  async getScanHistory(limit = 50, offset = 0) {
    try {
      const { data, error } = await this.supabase
        .from('scan_history')
        .select('*')
        .eq('user_id', 'anonymous')
        .order('created_at', { ascending: false })
        .range(offset, offset + limit - 1);

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Failed to load scan history:', error);
      return [];
    }
  }

  async deleteScanHistory(scanId) {
    try {
      const { error } = await this.supabase
        .from('scan_history')
        .delete()
        .eq('id', scanId);

      if (error) throw error;
      return true;
    } catch (error) {
      console.error('Failed to delete scan history:', error);
      return false;
    }
  }

  async clearOldHistory(retentionDays = 30) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const { error } = await this.supabase
        .from('scan_history')
        .delete()
        .lt('created_at', cutoffDate.toISOString());

      if (error) throw error;
      return true;
    } catch (error) {
      console.error('Failed to clear old history:', error);
      return false;
    }
  }

  // User Settings Management
  async saveSetting(key, value) {
    try {
      const { data, error } = await this.supabase
        .from('user_settings')
        .upsert({
          user_id: 'anonymous',
          setting_key: key,
          setting_value: value,
          updated_at: new Date().toISOString()
        });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Failed to save setting:', error);
      throw error;
    }
  }

  async getSetting(key, defaultValue = null) {
    try {
      const { data, error } = await this.supabase
        .from('user_settings')
        .select('setting_value')
        .eq('user_id', 'anonymous')
        .eq('setting_key', key)
        .single();

      if (error) {
        if (error.code === 'PGRST116') { // No rows returned
          return defaultValue;
        }
        throw error;
      }
      
      return data.setting_value;
    } catch (error) {
      console.error('Failed to get setting:', error);
      return defaultValue;
    }
  }

  async getAllSettings() {
    try {
      const { data, error } = await this.supabase
        .from('user_settings')
        .select('setting_key, setting_value')
        .eq('user_id', 'anonymous');

      if (error) throw error;
      
      const settings = {};
      data.forEach(row => {
        settings[row.setting_key] = row.setting_value;
      });
      
      return settings;
    } catch (error) {
      console.error('Failed to get all settings:', error);
      return {};
    }
  }

  // Rate Limiting Tracking
  async trackApiRequest(endpoint) {
    try {
      const windowStart = new Date();
      const windowEnd = new Date(windowStart.getTime() + 60000); // 1 minute window
      
      const { data, error } = await this.supabase
        .from('rate_limit_tracking')
        .insert({
          user_id: 'anonymous',
          api_endpoint: endpoint,
          window_start: windowStart.toISOString(),
          window_end: windowEnd.toISOString()
        });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Failed to track API request:', error);
    }
  }

  async getRateLimitStatus(endpoint, windowMinutes = 1) {
    try {
      const windowStart = new Date();
      windowStart.setMinutes(windowStart.getMinutes() - windowMinutes);

      const { data, error } = await this.supabase
        .from('rate_limit_tracking')
        .select('*')
        .eq('user_id', 'anonymous')
        .eq('api_endpoint', endpoint)
        .gte('created_at', windowStart.toISOString());

      if (error) throw error;
      
      return {
        requestCount: data.length,
        windowStart: windowStart.toISOString(),
        requests: data
      };
    } catch (error) {
      console.error('Failed to get rate limit status:', error);
      return { requestCount: 0, windowStart: new Date().toISOString(), requests: [] };
    }
  }

  // Queue Management
  async addToQueue(queueItem) {
    try {
      const { data, error } = await this.supabase
        .from('scan_queue')
        .insert({
          user_id: 'anonymous',
          scan_type: queueItem.type,
          target_name: queueItem.name,
          target_data: queueItem,
          priority: queueItem.priority || 0,
          status: 'queued'
        });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Failed to add to queue:', error);
      throw error;
    }
  }

  async updateQueueStatus(queueId, status, errorMessage = null) {
    try {
      const updateData = {
        status,
        updated_at: new Date().toISOString()
      };

      if (status === 'processing') {
        updateData.started_at = new Date().toISOString();
      } else if (status === 'completed' || status === 'failed') {
        updateData.completed_at = new Date().toISOString();
      }

      if (errorMessage) {
        updateData.error_message = errorMessage;
      }

      const { data, error } = await this.supabase
        .from('scan_queue')
        .update(updateData)
        .eq('id', queueId);

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Failed to update queue status:', error);
      throw error;
    }
  }

  async getQueueItems(status = null) {
    try {
      let query = this.supabase
        .from('scan_queue')
        .select('*')
        .eq('user_id', 'anonymous')
        .order('priority', { ascending: false })
        .order('created_at', { ascending: true });

      if (status) {
        query = query.eq('status', status);
      }

      const { data, error } = await query;
      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Failed to get queue items:', error);
      return [];
    }
  }

  async clearQueue() {
    try {
      const { error } = await this.supabase
        .from('scan_queue')
        .delete()
        .eq('user_id', 'anonymous');

      if (error) throw error;
      return true;
    } catch (error) {
      console.error('Failed to clear queue:', error);
      return false;
    }
  }

  // Statistics and Analytics
  async getStats() {
    try {
      const { data, error } = await this.supabase
        .from('scan_history')
        .select('scan_status, malicious_count, created_at')
        .eq('user_id', 'anonymous');

      if (error) throw error;

      const today = new Date().toDateString();
      const stats = {
        totalScans: data.length,
        todayScans: data.filter(scan => 
          new Date(scan.created_at).toDateString() === today
        ).length,
        threatsFound: data.filter(scan => scan.malicious_count > 0).length,
        cleanFiles: data.filter(scan => scan.malicious_count === 0).length
      };

      return stats;
    } catch (error) {
      console.error('Failed to get stats:', error);
      return {
        totalScans: 0,
        todayScans: 0,
        threatsFound: 0,
        cleanFiles: 0
      };
    }
  }
}

// Export for use in popup.js
window.DatabaseManager = DatabaseManager;