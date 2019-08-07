import Notification from '../schemas/Notification';
import User from '../models/User';

class NotificationController {
  async index(req, res) {
    const checkIsProvider = await User.findOne({
      where: { id: req.userId, provider: true },
    });

    if (!checkIsProvider) {
      res.status(401).json({
        error: { message: 'Only providers can load notifications' },
      });
    }

    const notifications = await Notification.find({ user: req.userId })
      .sort({ createdAt: 'desc' })
      .limit(20);

    return res.json(notifications);
  }

  async update(req, res) {
    try {
      const notification = await Notification.findByIdAndUpdate(
        req.params.id,
        { read: true },
        { new: true }
      );

      return res.json(notification);
    } catch (error) {
      return res
        .status(400)
        .json({ error: { message: 'Notification not found' } });
    }
  }
}

export default new NotificationController();
